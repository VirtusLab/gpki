import os
from pathlib import Path
from typing import List

from git_pki.custom_types import AddIdentityRequest, ImportRequest, Branch, FileChange, PREVIOUS_BRANCH, Request, RevokeIdentityRequest
from git_pki.utils import mkdir, shell


class Git:
    def __init__(self, root_dir):
        self.root_dir = root_dir
        self.identity_dir = f"{root_dir}/identities"
        self.key_dir = f"{root_dir}/keys"

    def update(self, listener) -> List:
        if Path(f"{self.root_dir}/.git").is_dir():
            # TODO (#21): reenable
            # branch=shell(self.home, "git rev-parse --abbrev-ref HEAD")
            # old_hash=shell(self.home, "git rev-parse HEAD")
            # shell(self.home, f"git pull origin {branch}")
            # new_hash=shell(self.home, "git rev-parse HEAD")

            # if old_hash != new_hash:
            # 	raw_output = shell(self.home, f'git diff --name-status "{old_hash}".."{new_hash}" | sort')
            # 	for line in filter(None, raw_output.split("\n")):
            # 		op, path = line.split('\t')
            # 		if 	 op == 'A': listener.key_added(path)
            # 		elif op == 'M': listener.key_updated(path)
            # 		elif op == 'R': listener.key_removed(path)
            pass
        else:

            repo = input("Specify git repository: ")
            shell(self.root_dir, f"git clone {repo} {self.root_dir}")
            mkdir(self.identity_dir)
            mkdir(self.key_dir)

            print(self.identity_dir)
            for path in os.listdir(self.identity_dir):
                listener.key_added(path)

            for path in os.listdir(self.key_dir):
                listener.key_added(path)

    def push_branch(self, branch, message):
        # TODO (#13): recover on failure
        shell(self.root_dir, f"git checkout -b {branch}")
        shell(self.root_dir, "git add -A")
        self.commit(message)
        self.push(branch)
        self.checkout(PREVIOUS_BRANCH)

    def push(self, branch):
        shell(self.root_dir, f"git push origin {branch}")

    def pull(self, branch):
        shell(self.root_dir, f"git pull origin {branch}")

    def merge(self, branch):
        shell(self.root_dir, f"git merge {branch}")

    def fetch(self, prune=False):
        shell(self.root_dir, f"git fetch origin {'--prune' if prune else ''}")

    def commit(self, message):
        shell(self.root_dir, f"git commit -m '{message}'")

    def add(self, path):
        shell(self.root_dir, f"git add {path}")

    def list_branches_unmerged_to_remote_counterpart_of(self, branch):
        raw = shell(self.root_dir, f"git branch --remotes --no-merged origin/{branch}").splitlines()
        strip = lambda line: line.strip()
        to_tuple = lambda branch: Request(branch, self.__commit_title(branch))
        return map(to_tuple, map(strip, raw))

    def get_local_branches(self):
        return shell(self.root_dir, 'git branch').replace('\n', '').split()

    def checkout(self, branch_name):
        shell(self.root_dir, f"git checkout {branch_name} --")

    def remove_local_branch(self, branch):
        shell(self.root_dir, f"git branch -D {branch}")

    def remove_remote_branch(self, branch):
        shell(self.root_dir, f"git push origin --delete {branch}")

    def file_diff(self, branch):
        raw = shell(self.root_dir, f'git diff --name-status HEAD.."{branch}" | sort').splitlines()
        strip = lambda line: line.split("\t")
        to_tuple = lambda segments: FileChange(segments[0], segments[1])
        return map(to_tuple, map(strip, raw))

    def open_worktree(self, directory, branch):
        path = Path(f"{directory}/{branch}")
        shell(self.root_dir, f"git worktree add {path} {branch}")
        return Git(path)

    def close_worktree(self, branch):
        shell(self.root_dir, f"git worktree remove {branch}")

    def current_branch(self):
        return shell(self.root_dir, "git rev-parse --abbrev-ref HEAD")

    def __commit_title(self, ref):
        return shell(self.root_dir, f"git log -1 --format=%s {ref}").strip()

    def __update_repository(self):
        pass

    def path_to(self, path):
        return Path(f"{self.root_dir}/{path}")

    def is_mergeable_to(self, base_branch, head_branch):
        merge_base = shell(self.root_dir, f"git merge-base {head_branch} {base_branch}").strip()
        output = shell(self.root_dir, f"git merge-tree {merge_base} {base_branch} {head_branch}").strip()
        return 'changed in both' not in output  # most probably there will be conflict when 'change in both' is present

    def get_request(self, request):
        if "import" in request.branch:
            return self.parse_import_request(request)
        else:
            if 'revoke' in request.branch:
                return self.parse_revokeidentity_request(request)
            else:
                return self.parse_addidentity_request(request)

    def parse_addidentity_request(self, request):
        name = request.branch.split('/')[-2]
        fingerprint = request.branch.split('/')[-1]
        branch = Branch('origin', '/'.join([name, fingerprint]), request.branch)
        return AddIdentityRequest(branch,
                                  name,
                                  fingerprint,
                                  self.path_to(f'identities/{name}/{fingerprint}'))

    def parse_revokeidentity_request(self, request):
        name = request.branch.split('/')[-2]
        fingerprint_revoked = request.branch.split('/')[-1]
        fingerprint = fingerprint_revoked.split('_')[0]
        branch = Branch('origin', '/'.join([name, fingerprint_revoked]), request.branch)
        return RevokeIdentityRequest(branch,
                                     name,
                                     fingerprint,
                                     self.path_to(f'identities/{name}/{fingerprint}_revoked'))


    def parse_import_request(self, request):
        import_hash = request.branch.split('/')[-1]
        branch = Branch('origin', '/'.join(['import', import_hash]), request.branch)
        return ImportRequest(branch, import_hash)

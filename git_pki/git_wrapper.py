import os
from pathlib import Path
from typing import List

from git_pki.custom_types import FileChange, Request
from git_pki.utils import get_file_list, mkdir, shell


class Git:
    def __init__(self, root_dir):
        self.root_dir = root_dir
        self.identity_dir = f"{root_dir}/identities"
        self.key_dir = f"{root_dir}/keys"
        self.__backup_files_cached = []

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

    def push(self, branch, message):
        # TODO (#13): recover on failure
        shell(self.root_dir, f"git checkout -b {branch}")
        shell(self.root_dir, "git add -A")
        shell(self.root_dir, f"git commit -m '{message}'")
        shell(self.root_dir, f"git push origin {branch}")
        shell(self.root_dir, "git checkout -")

    def list_branches_unmerged_to_remote_counterpart_of(self, branch):
        raw = shell(self.root_dir, f"git branch -a --no-merged origin/{branch}").splitlines()
        strip = lambda line: line.strip()
        to_tuple = lambda branch: Request(branch, self.__commit_title(branch))
        return map(to_tuple, map(strip, raw))

    def get_local_branches(self):
        return shell(self.root_dir, 'git branch').replace('\n', '').split()

    def checkout(self, branch_name):
        shell(self.root_dir, f"git checkout {branch_name}")

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

    def get_public_key_file_path(self, fingerprint):
        if not self.__backup_files_cached:
            self.__backup_files_cached = get_file_list(self.root_dir)
        for file in self.__backup_files_cached:
            if file.endswith(fingerprint):
                return file

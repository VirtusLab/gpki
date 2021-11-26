import os
from pathlib import Path
from typing import List

from constants import FileChange, Request
from utils import mkdir, shell


class Git:
    def __init__(self, home):
        self.home = home
        self.identity_dir = f"{home}/identities"
        self.key_dir = f"{home}/keys"

    def update(self, listener) -> List:
        if Path(f"{self.home}/.git").is_dir():
            # TODO reenable
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
            shell(self.home, f"git clone {repo} {self.home}")
            mkdir(self.identity_dir)
            mkdir(self.key_dir)

            print(self.identity_dir)
            for path in os.listdir(self.identity_dir):
                listener.key_added(path)

            for path in os.listdir(self.key_dir):
                listener.key_added(path)

    def push(self, branch, message):
        # TODO recover on failure!
        shell(self.home, f"git checkout -b {branch}")
        shell(self.home, "git add -A")
        shell(self.home, f"git commit -m '{message}'")
        shell(self.home, f"git push origin {branch}")
        shell(self.home, "git checkout -")
        shell(self.home, f"git branch -D {branch}")

    def list_unmerged_branches(self):
        branch = self.__current_branch()
        raw = shell(self.home, f"git branch -a --no-merged origin/{branch}").splitlines()
        strip = lambda line: line.strip()
        to_tuple = lambda branch: Request(branch, self.__commit_title(branch))
        return map(to_tuple, map(strip, raw))

    def file_diff(self, branch):
        raw = shell(self.home, f'git diff --name-status HEAD.."{branch}" | sort').splitlines()
        strip = lambda line: line.split("\t")
        to_tuple = lambda segments: FileChange(segments[0], segments[1])
        return map(to_tuple, map(strip, raw))

    def open_worktree(self, directory, branch):
        path = Path(f"{directory}/{branch}")
        shell(self.home, f"git worktree add {path} {branch}")
        return Git(path)

    def close_worktree(self, branch):
        shell(self.home, f"git worktree remove {branch}")

    def __current_branch(self):
        return shell(self.home, "git rev-parse --abbrev-ref HEAD")

    def __commit_title(self, ref):
        return shell(self.home, f"git log -1 --format=%s {ref}").strip()

    def __update_repository(self):
        pass

    def path_to(self, path):
        return Path(f"{self.home}/{path}")

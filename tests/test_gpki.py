import os
import subprocess
import random
import string
import sys
import re

from io import StringIO
from contextlib import redirect_stdout
from git_pki.gpki import GPKI
from unittest import TestCase
from unittest.mock import patch
from git_pki.utils import shell


def mock_iterfzf(base_container, prompt=""):
    return list(base_container)[0]


def overwrite_stdin(*args, **kwargs):
    def wrapper(func):
        original_stdin = sys.stdin
        sys.stdin = kwargs['message']
        func()
        sys.stdin = original_stdin
    return wrapper


class GitRepositorySandbox:
    def __init__(self):
        with os.popen("mktemp -d") as temp_remote_folder:
            self.remote_path = temp_remote_folder.read().strip()

        with os.popen("mktemp -d") as temp_local_folder:
            self.local_path = temp_local_folder.read().strip()

    def execute(self, command: str) -> "GitRepositorySandbox":
        subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True)
        return self

    def new_repo(self, *args: str) -> "GitRepositorySandbox":
        os.chdir(args[0])
        opts = args[1:]
        self.execute(f"git init {' '.join(opts)}")
        return self

    def new_branch(self, branch_name: str) -> "GitRepositorySandbox":
        self.execute(f"git checkout -b {branch_name}")
        return self

    def commit(self, message: str = "Some commit message.") -> "GitRepositorySandbox":
        f = "%s.txt" % "".join(random.choice(string.ascii_letters) for _ in range(20))
        self.execute(f"touch {f}")
        self.execute(f"git add {f}")
        self.execute(f'git commit -m "{message}"')
        return self

    def push(self) -> "GitRepositorySandbox":
        with os.popen("git symbolic-ref -q --short HEAD") as git_call:
            branch = git_call.read()
        self.execute(f"git push -u origin {branch}")
        return self


class GitPKI_Tester(TestCase):

    @staticmethod
    def get_temp_directory():
        with os.popen("mktemp -d") as temp_directory:
            temp_directory_path = temp_directory.read().strip()
        return temp_directory_path

    @staticmethod
    def exctract_gnupg_message(raw_output):
        match_obj = re.search("-----BEGIN PGP MESSAGE-----(.|\n)*-----END PGP MESSAGE-----", raw_output)
        if match_obj:
            return match_obj.group()
        else:
            raise EnvironmentError("Gnupg message not found in given data.")

    def setUp(self):
        self.repo_sandbox = GitRepositorySandbox()
        (
            self.repo_sandbox
            # Create the remote and sandbox repos, chdir into sandbox repo
            .new_repo(self.repo_sandbox.remote_path, "--bare")
            .new_repo(self.repo_sandbox.local_path)
            .execute(f"git remote add origin {self.repo_sandbox.remote_path}")
            .execute('git config user.email "tester@test.com"')
            .execute('git config user.name "Tester Test"')
            .new_branch("master")
            .commit("initial commit")
            .push()
        )

    def test_add_identity(self):
        temp_dir_name = GitPKI_Tester.get_temp_directory()
        with patch('builtins.input', return_value=self.repo_sandbox.remote_path) as _:
            gpki = GPKI(temp_dir_name)
        gpki.generate_identity('tester', 'tester@test.com', 'empty description', passphrase='strong_password')
        branches = shell(os.path.join(temp_dir_name, 'vault', 'public'), 'git branch -a')
        self.assertIn('remotes/origin/tester', branches)

    @patch('iterfzf.iterfzf', mock_iterfzf)
    def test_encrypt_decrypt_message(self):
        with patch('builtins.input', return_value=self.repo_sandbox.remote_path) as _:
            gpki = GPKI(GitPKI_Tester.get_temp_directory())
        gpki.generate_identity('tester', 'tester@test.com', 'empty description', passphrase='strong_password')

        original_stdin = sys.stdin
        sys.stdin = StringIO("Let's try to encrypt this message")
        with StringIO() as out:
            with redirect_stdout(out):
                gpki.encrypt(None, None)
            raw_output = out.getvalue()

        encrypted_message = self.exctract_gnupg_message(raw_output)

        sys.stdin = StringIO(encrypted_message)
        with StringIO() as out:
            with redirect_stdout(out):
                gpki.decrypt(None, None)
            raw_output = out.getvalue()

        sys.stdin = original_stdin
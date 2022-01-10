import os
import random
import re
import string
import subprocess
import sys

from contextlib import redirect_stdout
from io import StringIO
from unittest import TestCase
from unittest.mock import patch

from git_pki.gpki import GPKI
from git_pki.git_wrapper import Git
from git_pki.utils import shell


def mock_iterfzf(base_container, prompt=""):
    return list(base_container)[0]


def mock_getpass(prompt):
    return "strong_password"


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

    def check_out(self, branch: str):
        self.execute(f"git checkout -q {branch}")
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
        with patch('builtins.input', return_value=self.repo_sandbox.remote_path) as _:  # handle asking for repository while first use
            gpki = GPKI(temp_dir_name)
        gpki.generate_identity('tester', 'tester@test.com', 'empty description', passphrase='strong_password')
        branches = shell(os.path.join(temp_dir_name, 'vault', 'public'), 'git branch -a')
        self.assertIn('remotes/origin/tester', branches)  # TODO (#36): rely on changes in Keys

    @patch('getpass.getpass', mock_getpass)  # need to walkaround interactive ask for passphrase
    @patch('iterfzf.iterfzf', mock_iterfzf)  # in tests we got only one identity per test, so we can easily get the first one and move on
    def test_encrypt_decrypt_message(self):
        with patch('builtins.input', return_value=self.repo_sandbox.remote_path) as _:  # handle asking for repository while first use
            gpki = GPKI(GitPKI_Tester.get_temp_directory())
        gpki.generate_identity('tester', 'tester@test.com', 'empty description', passphrase='strong_password')

        stdin_backup = sys.stdin
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

        sys.stdin = stdin_backup
        relevant_message = raw_output.split('\n')[-2]
        self.assertIn("Let's try to encrypt this message", raw_output)
        self.assertEqual("Let's try to encrypt this message", relevant_message)

    @patch('getpass.getpass', mock_getpass)  # need to walkaround interactive ask for passphrase
    @patch('iterfzf.iterfzf', mock_iterfzf)  # in tests we got only one identity per test, so we can easily get the first one and move on
    def test_encrypt_to_file_decrypt_from_file(self):
        with patch('builtins.input', return_value=self.repo_sandbox.remote_path) as _:  # handle asking for repository while first use
            gpki = GPKI(GitPKI_Tester.get_temp_directory())
        gpki.generate_identity('tester', 'tester@test.com', 'empty description', passphrase='strong_password')

        message = "confidencial test message"

        stdin_backup = sys.stdin
        sys.stdin = StringIO(message)
        with StringIO() as out:
            gpki.encrypt(None, 'output.txt')

        with StringIO() as out:
            with redirect_stdout(out):
                gpki.decrypt('output.txt', None)
            raw_output = out.getvalue()

        sys.stdin = stdin_backup
        decrypted_output = raw_output.split('\n')[-2]

        self.assertIn(message, raw_output)
        self.assertEqual(message, decrypted_output)

    @patch('getpass.getpass', mock_getpass)  # need to walkaround interactive ask for passphrase
    @patch('iterfzf.iterfzf', mock_iterfzf)  # in tests we got only one identity per test, so we can easily get the first one and move on
    def test_encrypt_from_file_to_file_decrypt_from_file_to_file(self):
        with patch('builtins.input', return_value=self.repo_sandbox.remote_path) as _:  # handle asking for repository while first use
            gpki = GPKI(GitPKI_Tester.get_temp_directory())
        gpki.generate_identity('tester', 'tester@test.com', 'empty description', passphrase='strong_password')

        message = "Strong encryption"
        with open('confidencial_source_file', "w") as file:
            file.write(message)

        gpki.encrypt('confidencial_source_file', 'encrypted_output')
        gpki.decrypt('encrypted_output', 'decrypted_file')

        with open('confidencial_source_file', "r") as file:
            initial_msg = file.read()

        with open('decrypted_file', "r") as decrypted_file:
            decrypted_file_body = decrypted_file.read()

        self.assertEqual(initial_msg, decrypted_file_body)

    def test_import_keys_from_file(self):
        test_dir = os.path.abspath(__file__)
        with patch('builtins.input', return_value=self.repo_sandbox.remote_path) as _:  # handle asking for repository while first use
            gpki = GPKI(GitPKI_Tester.get_temp_directory())

        with patch('builtins.input', return_value='y') as _:  # To confirm that file contains proper keys
            with StringIO() as out:
                with redirect_stdout(out):
                    gpki.import_keys([test_dir.replace('test_gpki.py', 'test_keys_input.txt')])
                raw_output = out.getvalue()

        desired_output = ('Import Summary:\n\n'
                          'Unchanged:\n'
                          'b6f66d4bff2264f7be13f31dbc635375b29cd83a 2021-12-14 2022-06-12 pioter None None\n\n'  
                          'Succeded:\n'
                          'fe0f710be0fbde4ac0384bf4c9a8dfbd8930675c 2021-12-13 2022-06-11 pio None None\n'  
                          'b6f66d4bff2264f7be13f31dbc635375b29cd83a 2021-12-14 2022-06-12 pioter None None\n'
                          '5ec643aba5e71827805eff7b297226aeb797e70c 2021-12-20 2022-06-18 p3 None None')

        self.assertIn(desired_output, raw_output)

        with patch('builtins.input', return_value='y') as _:  # To confirm that file contains proper keys
            with StringIO() as out:
                with redirect_stdout(out):
                    gpki.import_keys([test_dir.replace('test_gpki.py', 'test_keys_input.txt')])
                raw_output = out.getvalue()

        desired_output = ('\nImport Summary:\n\n'
                          'Unchanged:\n'
                          'fe0f710be0fbde4ac0384bf4c9a8dfbd8930675c 2021-12-13 2022-06-11 pio None None\n'
                          'b6f66d4bff2264f7be13f31dbc635375b29cd83a 2021-12-14 2022-06-12 pioter None None\n'
                          'b6f66d4bff2264f7be13f31dbc635375b29cd83a 2021-12-14 2022-06-12 pioter None None\n'
                          '5ec643aba5e71827805eff7b297226aeb797e70c 2021-12-20 2022-06-18 p3 None None')

        self.assertIn(desired_output, raw_output)

    def test_accept_pr(self):
        with patch('builtins.input', return_value=self.repo_sandbox.remote_path) as _:  # handle asking for repository while first use
            test_dir = GitPKI_Tester.get_temp_directory()
            gpki = GPKI(test_dir)
            git = Git(test_dir + '/vault/public')
            gpki.generate_identity('tester', 'tester@test.com', 'empty description', passphrase='strong_password')

        unmerged_branch = list(git.list_branches_unmerged_to_remote_counterpart_of('master'))[0].branch
        request_fingerprint_file_name = unmerged_branch.split('/')[-1]
        expected_file_list = [request_fingerprint_file_name]
        with patch('builtins.input', side_effect=[0, 'y']) as _:  # 0 to take first pr and 'y' to approve it
            gpki.review_requests()

        # now check if master has desired key
        self.repo_sandbox.check_out('master')
        files = []
        for root, dirs, files_in_dir in os.walk(test_dir + '/vault/public/identities/'):
            for file in files_in_dir:
                files.append(file)

        self.assertEqual(len(files), 1)
        self.assertEqual(expected_file_list, files)

        # check if accepted branch was removed from remote
        remote_branches = shell(os.path.join(test_dir, 'vault', 'public'), 'git branch -r').strip().split(' ')
        self.assertNotIn('origin/' + unmerged_branch, remote_branches)

    def test_reject_pr_without_branch_deletion(self):
        with patch('builtins.input', return_value=self.repo_sandbox.remote_path) as _:  # handle asking for repository while first use
            test_dir = GitPKI_Tester.get_temp_directory()
            gpki = GPKI(test_dir)
            git = Git(test_dir + '/vault/public')
            gpki.generate_identity('tester', 'tester@test.com', 'empty description', passphrase='strong_password')


        unmerged_branch = list(git.list_branches_unmerged_to_remote_counterpart_of('master'))[0].branch
        with patch('builtins.input', side_effect=[0, 'n', 'n']) as _:  # 0 to take first pr and 'n' to reject it, second 'n' to not delete branch
            gpki.review_requests()

        # make sure that master does not have key from pr
        self.repo_sandbox.check_out('master')
        files = []
        for root, dirs, files_in_dir in os.walk(test_dir + '/vault/public/identities'):
            for file in files_in_dir:
                files.append(file)

        self.assertEqual([], files)

        # pr branch should be still available on remote
        remote_branches = shell(os.path.join(test_dir, 'vault', 'public'), 'git branch -r').strip().split(' ')
        self.assertIn(unmerged_branch, remote_branches)

    def test_reject_pr_with_branch_deletion(self):
        with patch('builtins.input', return_value=self.repo_sandbox.remote_path) as _:  # handle asking for repository while first use
            test_dir = GitPKI_Tester.get_temp_directory()
            gpki = GPKI(test_dir)
            git = Git(test_dir + '/vault/public')
            gpki.generate_identity('tester', 'tester@test.com', 'empty description', passphrase='strong_password')


        unmerged_branch = list(git.list_branches_unmerged_to_remote_counterpart_of('master'))[0].branch
        with patch('builtins.input', side_effect=[0, 'n', 'y']) as _:  # 0 to take first pr and 'n' to reject it, second 'y' to delete branch
            gpki.review_requests()

        # make sure that master does not have key from pr
        self.repo_sandbox.check_out('master')
        files = []
        for root, dirs, files_in_dir in os.walk(test_dir + '/vault/public/identities'):
            for file in files_in_dir:
                files.append(file)

        self.assertEqual([], files)

        # pr branch should be still available on remote
        remote_branches = shell(os.path.join(test_dir, 'vault', 'public'), 'git branch -r').strip().split(' ')
        self.assertNotIn('origin/' + unmerged_branch, remote_branches)

    def test_accept_pr_from_imported_keys(self):
        root_dir = os.path.abspath(__file__)
        with patch('builtins.input', return_value=self.repo_sandbox.remote_path) as _:  # handle asking for repository while first use
            test_dir = GitPKI_Tester.get_temp_directory()
            gpki = GPKI(test_dir)
            git = Git(test_dir + '/vault/public')

        with patch('builtins.input', return_value='y') as _:  # To confirm that file contains proper keys
            with StringIO() as out:
                with redirect_stdout(out):
                    gpki.import_keys([root_dir.replace('test_gpki.py', 'tester_exported.txt')])
                raw_output = out.getvalue()

        unmerged_branch = list(git.list_branches_unmerged_to_remote_counterpart_of('master'))[0].branch
        expected_file_list = ['5e42d830dcf16917dc7179bd196d044b1fdcc3e6']
        with patch('builtins.input', side_effect=[0, 'y']) as _:  # 0 to take first pr and 'y' to approve it
            gpki.review_requests()

        # now check if master has desired key
        self.repo_sandbox.check_out('master')
        files = []
        for root, dirs, files_in_dir in os.walk(test_dir + '/vault/public/identities/'):
            for file in files_in_dir:
                files.append(file)

        self.assertEqual(len(files), 1)
        self.assertEqual(expected_file_list, files)

        # check if accepted branch was removed from remote
        remote_branches = shell(os.path.join(test_dir, 'vault', 'public'), 'git branch -r').strip().split(' ')
        self.assertNotIn('origin/' + unmerged_branch, remote_branches)

    def test_accept_pr_from_imported_multiple_keys(self):
        root_dir = os.path.abspath(__file__)
        with patch('builtins.input',
                   return_value=self.repo_sandbox.remote_path) as _:  # handle asking for repository while first use
            test_dir = GitPKI_Tester.get_temp_directory()
            gpki = GPKI(test_dir)
            git = Git(test_dir + '/vault/public')

        with patch('builtins.input', return_value='y') as _:  # To confirm that file contains proper keys
            with StringIO() as out:
                with redirect_stdout(out):
                    gpki.import_keys([root_dir.replace('test_gpki.py', 'tester_exported_multiple.txt')])
                raw_output = out.getvalue()

        unmerged_branch = list(git.list_branches_unmerged_to_remote_counterpart_of('master'))[0].branch
        expected_file_list = ['5e42d830dcf16917dc7179bd196d044b1fdcc3e6', 'bff0a80ce6b1aca266e017b134ed88b13c45a6ef']
        with patch('builtins.input', side_effect=[0, 'y']) as _:  # 0 to take first pr and 'y' to approve it
            gpki.review_requests()

        # now check if master has desired key
        self.repo_sandbox.check_out('master')
        files = []
        for root, dirs, files_in_dir in os.walk(test_dir + '/vault/public/identities/'):
            for file in files_in_dir:
                files.append(file)

        self.assertEqual(len(files), 2)
        self.assertEqual(expected_file_list, files)

        # check if accepted branch was removed from remote
        remote_branches = shell(os.path.join(test_dir, 'vault', 'public'), 'git branch -r').strip().split(' ')
        self.assertNotIn('origin/' + unmerged_branch, remote_branches)

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

import git_pki.gpg_wrapper
from git_pki.exceptions import Git_PKI_Exception
from git_pki.gpki import GPKI
from git_pki.git_wrapper import Git
from git_pki.utils import shell


def mock_iterfzf(base_container, prompt="", multi=False):
    return list(base_container) if multi else list(base_container)[0]


def mock_getpass(prompt):
    return "strong_password"


def mock_export_public_key(cls, name):
    return cls.gpg.export_keys(name, True, passphrase="strong_password")


def set_git_username_email(path_to_repo):
    shell(os.path.join(path_to_repo, 'vault', 'public'), 'git config user.email "tester@test.com"')
    shell(os.path.join(path_to_repo, 'vault', 'public'), 'git config user.name "Tester Test"')


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
            set_git_username_email(temp_dir_name)
        gpki.generate_identity('tester', 'tester@test.com', 'empty description', passphrase='strong_password')
        branches = shell(os.path.join(temp_dir_name, 'vault', 'public'), 'git branch -a')
        self.assertIn('remotes/origin/tester', branches)  # TODO (#36): rely on changes in Keys

    @patch('getpass.getpass', mock_getpass)  # need to walkaround interactive ask for passphrase
    @patch('iterfzf.iterfzf', mock_iterfzf)  # in tests we got only one identity per test, so we can easily get the first one and move on
    def test_encrypt_decrypt_message(self):
        temp_dir_name = GitPKI_Tester.get_temp_directory()
        with patch('builtins.input', return_value=self.repo_sandbox.remote_path) as _:  # handle asking for repository while first use
            gpki = GPKI(temp_dir_name)
            set_git_username_email(temp_dir_name)
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
        temp_dir_name = GitPKI_Tester.get_temp_directory()
        with patch('builtins.input', return_value=self.repo_sandbox.remote_path) as _:  # handle asking for repository while first use
            gpki = GPKI(temp_dir_name)
            set_git_username_email(temp_dir_name)
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
        temp_dir_name = GitPKI_Tester.get_temp_directory()
        with patch('builtins.input', return_value=self.repo_sandbox.remote_path) as _:  # handle asking for repository while first use
            gpki = GPKI(temp_dir_name)
            set_git_username_email(temp_dir_name)
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
        root_dir = os.path.abspath(__file__)
        with patch('builtins.input', return_value=self.repo_sandbox.remote_path) as _:  # handle asking for repository while first use
            test_dir = GitPKI_Tester.get_temp_directory()
            gpki = GPKI(test_dir)
            set_git_username_email(test_dir)

        with patch('builtins.input', return_value='y') as _:  # To confirm that file contains proper keys
            with StringIO() as out:
                with redirect_stdout(out):
                    gpki.import_keys([root_dir.replace('test_gpki.py', 'test_keys_input.txt')])
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
                    gpki.import_keys([root_dir.replace('test_gpki.py', 'test_keys_input.txt')])
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
            set_git_username_email(test_dir)
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
            set_git_username_email(test_dir)
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
            set_git_username_email(test_dir)
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
            set_git_username_email(test_dir)
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
            set_git_username_email(test_dir)
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

    @patch('git_pki.gpg_wrapper.GnuPGHandler.export_public_key', mock_export_public_key)  # need to export private key
    @patch('getpass.getpass', mock_getpass)  # need to walkaround interactive ask for passphrase
    @patch('iterfzf.iterfzf', mock_iterfzf)  # in tests we got only one identity per test, so we can easily get the first one and move on
    def test_revoke_key_by_overriding_identity(self):
        with patch('builtins.input', return_value=self.repo_sandbox.remote_path) as _:  # handle asking for repository while first use
            test_dir = GitPKI_Tester.get_temp_directory()
            gpki = GPKI(test_dir)
            set_git_username_email(test_dir)
            git = Git(test_dir + '/vault/public')
            gpki.generate_identity('tester', 'tester@test.com', 'empty description', passphrase='strong_password')
            gpki.generate_identity('tester2', 'tester2@test.com', 'empty description', passphrase='strong_password')

        with patch('builtins.input', side_effect=[0, 'y']) as _:  # 0 to take first pr and 'y' to approve it
            gpki.review_requests()

        # also create a backup export of desired key, as it will be deleted from keyring
        backup_path = git.path_to('backup_key')
        gpki.export_keys(['tester'], backup_path)

        stdin_backup = sys.stdin
        sys.stdin = StringIO("Let's try to encrypt this message")
        with StringIO() as out:
            with redirect_stdout(out):
                gpki.encrypt(None, None)
            raw_output = out.getvalue()

        sys.stdin = stdin_backup
        encrypted_message = self.exctract_gnupg_message(raw_output)

        # now revoke the key by overridding identity
        with patch('builtins.input', side_effect=['y', 'y', '2022-01-01']) as _:
            gpki.generate_identity('tester', 'tester@test.com', 'empty description', passphrase='strong_password')

        # approve revoked key, merge into master
        gpki.merge_revoked()

        found_desired_revoked_file = False
        for root, dirs, files in os.walk(git.path_to('identities')):
            for f in files:
                if root.endswith('tester') and 'revoked' in f:
                    found_desired_revoked_file = True

        #  check if revoked key is found on master
        self.assertTrue(found_desired_revoked_file)

        # load revoked key again into keyring
        with patch('builtins.input', return_value='y') as _:
            gpki.import_keys([backup_path])

        # try to decrypt message with revoked key, expect to rise exception
        sys.stdin = StringIO(encrypted_message)
        with StringIO() as out:
            with redirect_stdout(out):
                with self.assertRaises(Git_PKI_Exception,
                                       msg='Could not decrypt message signed with revoked key and message was signed after revocation time.'):
                    gpki.decrypt(None, None)

    @patch('getpass.getpass', mock_getpass)  # need to walkaround interactive ask for passphrase
    @patch('iterfzf.iterfzf', mock_iterfzf)  # in tests we got only one identity per test, so we can easily get the first one and move on
    def test_revoke_key(self):
        with patch('builtins.input', return_value=self.repo_sandbox.remote_path) as _:  # handle asking for repository while first use
            test_dir = GitPKI_Tester.get_temp_directory()
            gpki = GPKI(test_dir)
            set_git_username_email(test_dir)
            git = Git(test_dir + '/vault/public')
            gpg_wrapped = git_pki.gpg_wrapper.GnuPGHandler(test_dir + "/vault/private")
            gpki.generate_identity('tester', 'tester@test.com', 'empty description', passphrase='strong_password')

        # approve freshly added identity
        with patch('builtins.input', side_effect=[0, 'y', ]) as _:
             gpki.review_requests()

        all_private_keys = list(gpg_wrapped.private_keys_list())
        pkey = all_private_keys[0]
        self.assertTrue(len(all_private_keys) == 1)

        with patch('builtins.input', side_effect=['y', '2022-01-01']) as _:
            gpki.revoke('tester')
        gpki.merge_revoked()

        all_private_keys_after_revoke = list(gpg_wrapped.private_keys_list())

        self.assertTrue(len(all_private_keys_after_revoke) == 0)

        # check if revoke branch is merged to master
        git.pull('master')
        add_identity_path = git.path_to(f'identities/{pkey.name}/{pkey.fingerprint}')
        revoke_path = git.path_to(f'identities/{pkey.name}/{pkey.fingerprint}_revoked')
        self.assertTrue(os.path.exists(add_identity_path))
        self.assertTrue(os.path.exists(revoke_path))


    @patch('getpass.getpass', mock_getpass)  # need to walkaround interactive ask for passphrase
    @patch('iterfzf.iterfzf', mock_iterfzf)  # in tests we got only one identity per test, so we can easily get the first one and move on
    def test_update(self):
        with patch('builtins.input', return_value=self.repo_sandbox.remote_path) as _:  # handle asking for repository while first use
            test_dir = GitPKI_Tester.get_temp_directory()
            gpki = GPKI(test_dir)
            set_git_username_email(test_dir)
            gpg_wrapped = git_pki.gpg_wrapper.GnuPGHandler(test_dir + "/vault/private")
            gpki.generate_identity('tester', 'tester@test.com', 'empty description', passphrase='strong_password')
            gpki.generate_identity('tester2', 'tester2@test.com', 'empty description', passphrase='strong_password')
            gpki.generate_identity('tester3', 'tester3@test.com', 'empty description', passphrase='strong_password')

        initial_keys = list(gpg_wrapped.public_keys_list())
        # approve all the keys
        with patch('builtins.input', side_effect=[0, 'y', 0, 'y', 0, 'y']) as _:
            for i in range(3):
                gpki.review_requests()

        # revoke first key and approve it
        with patch('builtins.input', side_effect=['y', 'y', '2022-01-01']) as _:
            gpki.generate_identity('tester', 'tester@test.com', 'empty description', passphrase='strong_password')
        gpki.merge_revoked()

        # remove all public keys from keyring
        gpki.remove_keys([key.fingerprint for key in initial_keys])

        # load again keys with `update` command
        gpki.update()

        final_keys = list(gpg_wrapped.public_keys_list())

        # now the only difference between initial and final keys should "tester" key
        key_difference = list(set(final_keys) - set(initial_keys))

        self.assertEqual(len(key_difference), 1)
        self.assertEqual(key_difference[0].name, initial_keys[0].name)
        self.assertNotEqual(key_difference[0].fingerprint, initial_keys[0].fingerprint)
        self.assertNotEqual(key_difference[0], initial_keys[0])

    @patch('getpass.getpass', mock_getpass)  # need to walkaround interactive ask for passphrase
    @patch('iterfzf.iterfzf', mock_iterfzf)  # take first and only signatory
    def test_encrypt_for_multiple_recipients(self):
        with patch('builtins.input', return_value=self.repo_sandbox.remote_path) as _:  # handle asking for repository while first use
            test_dir = GitPKI_Tester.get_temp_directory()
            gpki = GPKI(test_dir)
            set_git_username_email(test_dir)
            gpg_wrapped = git_pki.gpg_wrapper.GnuPGHandler(test_dir + "/vault/private")
            git = Git(test_dir + '/vault/public')
            gpki.generate_identity('tester', 'tester@test.com', 'empty description', passphrase='strong_password')
            gpki.generate_identity('tester2', 'tester2@test.com', 'empty description', passphrase='strong_password')
            gpki.generate_identity('tester3', 'tester3@test.com', 'empty description', passphrase='strong_password')
            gpki.generate_identity('tester4', 'tester4@test.com', 'empty description', passphrase='strong_password')

        # also create a backup export of desired key, as it will be deleted from keyring
        backup_path = git.path_to('backup_key')
        gpki.export_keys(['tester'], backup_path)

        for pkey in list(gpg_wrapped.private_keys_list())[:-1]:
            gpg_wrapped.remove_private_key(pkey, 'strong_password')

        # encrypt message with --all flag
        initial_message = 'Confidencial data propagated to all team members'
        stdin_backup = sys.stdin
        sys.stdin = StringIO(initial_message)
        with StringIO() as out:
            with redirect_stdout(out):
                gpki.encrypt(None, None, select_all_recipients=True)
            raw_output = out.getvalue()

        encrypted_message = self.exctract_gnupg_message(raw_output)

        for pkey in list(gpg_wrapped.public_keys_list())[:-1]:  # leave only one public key
            gpg_wrapped.remove_public_key(pkey)

        sys.stdin = StringIO(encrypted_message)
        with StringIO() as out:
            with redirect_stdout(out):
                gpki.decrypt(None, None)
            raw_output = out.getvalue()

        sys.stdin = stdin_backup
        relevant_message = raw_output.split('\n')[-2]
        self.assertIn(initial_message, raw_output)
        self.assertEqual(initial_message, relevant_message)

        # try to decrypt with different key
        for pkey in gpg_wrapped.private_keys_list():
            gpg_wrapped.remove_private_key(pkey, 'strong_password')

        with patch('builtins.input', return_value='y') as _:
            gpki.import_keys([backup_path])

        sys.stdin = StringIO(encrypted_message)
        with StringIO() as out:
            with redirect_stdout(out):
                gpki.decrypt(None, None)
            raw_output = out.getvalue()

        sys.stdin = stdin_backup
        relevant_message = raw_output.split('\n')[-2]
        self.assertIn(initial_message, raw_output)
        self.assertEqual(initial_message, relevant_message)

    @patch('getpass.getpass', mock_getpass)  # need to walkaround interactive ask for passphrase
    @patch('iterfzf.iterfzf', mock_iterfzf)  # take first and only signatory
    def test_revert_pr_add_identity(self):
        with patch('builtins.input', return_value=self.repo_sandbox.remote_path) as _:  # handle asking for repository while first use
            test_dir = GitPKI_Tester.get_temp_directory()
            gpki = GPKI(test_dir)
            set_git_username_email(test_dir)
            gpg_wrapped = git_pki.gpg_wrapper.GnuPGHandler(test_dir + "/vault/private")
            gpki.generate_identity('tester', 'tester@test.com', 'empty description', passphrase='strong_password')

        private_keys = list(gpg_wrapped.private_keys_list())
        self.assertTrue(len(private_keys) == 1)

        # now let's reject our identity
        with patch('builtins.input', side_effect=[0, 'n', 'y']) as _:
            gpki.review_requests()

        private_keys_after_review = list(gpg_wrapped.private_keys_list())
        self.assertEqual(private_keys, private_keys_after_review)

        gpki.update()

        # expect empty list
        final_private_keys = list(gpg_wrapped.private_keys_list())

        self.assertTrue(len(final_private_keys) == 0)

    @patch('getpass.getpass', mock_getpass)  # need to walkaround interactive ask for passphrase
    @patch('iterfzf.iterfzf', mock_iterfzf)  # take first and only signatory
    def test_revert_pr_import(self):
        root_dir = os.path.abspath(__file__)
        with patch('builtins.input', return_value=self.repo_sandbox.remote_path) as _:  # handle asking for repository while first use
            test_dir = GitPKI_Tester.get_temp_directory()
            gpki = GPKI(test_dir)
            set_git_username_email(test_dir)
            gpg_wrapped = git_pki.gpg_wrapper.GnuPGHandler(test_dir + "/vault/private")

        with patch('builtins.input', return_value='y') as _:
            gpki.import_keys([root_dir.replace('test_gpki.py', 'tester_exported_multiple.txt')])

        public_keys = list(gpg_wrapped.public_keys_list())
        self.assertTrue(len(public_keys) == 2)
        self.assertEqual([key.fingerprint for key in public_keys], ['bff0a80ce6b1aca266e017b134ed88b13c45a6ef', '5e42d830dcf16917dc7179bd196d044b1fdcc3e6'])

        # now let's reject our import request
        with patch('builtins.input', side_effect=[0, 'n', 'y']) as _:
            gpki.review_requests()

        public_keys_after_review = list(gpg_wrapped.public_keys_list())
        self.assertEqual(public_keys, public_keys_after_review)

        gpki.update()

        # expect empty list
        final_private_keys = list(gpg_wrapped.private_keys_list())

        self.assertTrue(len(final_private_keys) == 0)

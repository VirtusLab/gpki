#!/usr/local/bin/python3
import argparse
import os
import sys
import tempfile

import getpass
import iterfzf
from datetime import datetime, timezone
from pathlib import Path

import git_pki.gpg_wrapper
from git_pki import __version__
from git_pki.custom_types import KeyChange, ImportRequest, RevokeIdentityRequest
from git_pki.exceptions import Git_PKI_Exception
from git_pki.git_wrapper import Git
from git_pki.utils import file_exists, format_key, mkdir, read_multiline_string, sha1_encode
from git_pki import gpg_wrapper


class KeyChangeListener:
    def __init__(self, gpg):
        self.__gpg = gpg

    def key_added(self, path):
        print(f"A {path}")
        self.__gpg.import_public_key(path)

    def key_updated(self, path):
        print(f"M {path}")
        self.__gpg.import_public_key(path)

    def key_removed(self, path):
        print(f"R {path}")
        fingerprint = self.__gpg.file_key_fingerprint(path)
        self.__gpg.remove_public_key(fingerprint)


class GPKI:
    def __init__(self, home):
        self.__file_gpghome = mkdir(f"{home}/vault/private", 0o700)
        self.__file_repository = mkdir(f"{home}/vault/public")
        self.__review_dir = mkdir(f"{home}/reviews")
        self.__gpg = git_pki.gpg_wrapper.GnuPGHandler(self.__file_gpghome)
        self.__git = Git(self.__file_repository)

        listener = KeyChangeListener(self.__gpg)
        self.__git.update(listener)

    def generate_identity(self, name, email, description, passphrase=None):
        self.__git.checkout('master')
        existing_key = self.__gpg.private_key_fingerprint(name)
        if existing_key is not None:
            # If key exists, confirm removal of the private version and move public one to the archive
            response = input(f"Replace existing identity of {existing_key}? [yN] ")
            if response.lower() != "y":
                return
            self.revoke(priv_key_name=existing_key)

        fingerprint = self.__gpg.generate_key(name, email, description, passphrase=passphrase)
        if fingerprint is None:
            return

        key = self.__gpg.export_public_key(name)
        file = Path(f"{self.__git.identity_dir}/{name}/{fingerprint}")
        self.__export_key(key, Path(file))
        self.__git.push_branch(f"{name}/{fingerprint}", f"Publish key {name}/{fingerprint}")
        print(key)
        # TODO (#24): maybe find a way to revert changes if PR gets rejected ?
        #  fetch --prune, then check which branch is present locally and not on remote, then remove keys from selected branches
        #  move to update method and add flag to `update` <keep-rejected-keys>

    def revoke(self, priv_key_name=None):
        if priv_key_name is None:
            available_signatories = map(format_key, self.__gpg.private_keys_list())
            selection = iterfzf.iterfzf(available_signatories, prompt="Select private key to revoke ")
            to_revoke = None if selection is None else selection.split()[0]
            if to_revoke is None:
                return
            priv_key = self.__gpg.get_private_key_by_id(to_revoke)
        else:
            priv_key = self.__gpg.get_private_key_by_id(priv_key_name)

        passphrase = getpass.getpass(f"Specify passphrase for the existing key of [{priv_key.name}]: ")
        self.__gpg.remove_private_key(priv_key.fingerprint, passphrase)
        if input("Invalidate previous public key? [yN]\n").lower() == "y":  # remove this question, it's pointless to have public key when nobody has private key
            self.__gpg.remove_public_key(priv_key.fingerprint)
            ans = input("Specify expiration time in format YYYY-MM-DDTHH:mm:ss or leave empty to take current timestamp.")
            if ans == '':
                revocation_timestamp = datetime.now(timezone.utc)
            else:
                try:
                    revocation_timestamp = datetime.fromisoformat(ans)
                except ValueError:
                    Git_PKI_Exception(f"Unrecognized date: {ans}")
            revocation_timestamp = revocation_timestamp.replace(tzinfo=timezone.utc).strftime('%Y-%m-%d %H:%M:%S%z')

            # make RevokeIdentityRequest
            revoke_file = Path(f"{self.__git.identity_dir}/{priv_key.name}/{priv_key.fingerprint}_revoked")
            mkdir(revoke_file.parent)
            with open(revoke_file, 'w') as f:
                f.write(revocation_timestamp)
            self.__git.push_branch(f"{priv_key.name}/{priv_key.fingerprint}_revoked", f"Revoke key {priv_key.name}/{priv_key.fingerprint}")

    def list_signatories(self):
        print("fingerprint                              created-on expires-on\tidentity\temail\tdescription")
        for key in self.__gpg.private_keys_list():
            # TODO (#25): align the text correctly
            print(f"{key}")

    def list_recipients(self):
        print("fingerprint                              created-on expires-on\tidentity\temail\tdescription")
        for key in self.__gpg.public_keys_list():
            # TODO (#25): align the text correctly
            print(f"{key}")

    def encrypt(self, source, target, passphrase=None, select_all_recipients=False):
        if target is not None and os.path.isfile(target):
            if input(f"Target file already exist, do you want to overwrite? [yN] ").lower() != 'y':
                return
        available_recipients = list(map(format_key, self.__gpg.public_keys_list()))
        if select_all_recipients:
            selection = available_recipients
        else:
            selection = iterfzf.iterfzf(available_recipients, prompt="Select recipients (use tab to selected entry): ", multi=True)
            if selection is None:
                return

        recipients = [item.split()[0] for item in selection]

        available_signatories = map(format_key, self.__gpg.private_keys_list())
        selection = iterfzf.iterfzf(available_signatories, prompt="Select signatory or press ctrl+d to not sign ")
        signatory = None if selection is None else selection.split()[0]

        if not passphrase:
            passphrase = getpass.getpass(f"Specify passphrase for [{selection[0]}]: ")

        self.__gpg.encrypt(recipients, signatory, source, target, passphrase)

    def decrypt(self, source, target, passphrase=None, update=False):
        if update:
            self.update()
        if file_exists(target):
            if input(f"Target file already exist, do you want to overwrite? [yN] ").lower() != 'y':
                return

        if source is None:
            data = []
            print("Paste message, then press enter and ctrl+d")
            for line in sys.stdin:
                data.append(line)
            source = "".join(data)
            recipients = self.__gpg.get_recipients_from_message(source)
        elif os.path.isfile(source):
            with open(source, 'rb') as src_file:
                recipients = self.__gpg.get_recipients_from_file(src_file)
        else:
            print(f"Specified source file: {source} was not found, aborting.")
            return

        # Check if we have at least one private key to decrypt message
        priv_key = None
        for rec in recipients[::-1]:
            priv_key = self.__gpg.get_private_key_by_id(rec)
            if priv_key is not None:
                break

        if priv_key is None:
            raise Git_PKI_Exception("Could not find private key to decrypt message. Are you correct recipient?")
        if passphrase is None:
            passphrase = getpass.getpass(f"Specify passphrase for {priv_key.name}: ")

        self.verify_message(source, passphrase, update)
        self.__gpg.decrypt(source, target, passphrase)

    def verify_message(self, message, passphrase, updated):
        valid_key_list = []
        revoked_key_list = []
        signature_verification = self.__gpg.verify_signature(message, passphrase)
        for signature in signature_verification:
            key = self.__gpg.get_public_key_by_id(signature.signatory_fingerprint)
            if key is None:
                if updated:
                    raise Git_PKI_Exception("Could not verify message: signatory from outside organisation.")
                else:
                    self.update()
                    key = self.__gpg.get_public_key_by_id(signature.signatory_fingerprint)
                    if key is None:
                        raise Git_PKI_Exception("Could not verify message: signatory from outside organisation.")

            if self.is_key_revoked(key) and self.get_revocation_time(key) < datetime.fromtimestamp(float(signature.timestamp), tz=timezone.utc):
                revoked_key_list.append(key)
            else:
                valid_key_list.append(key)

        if len(revoked_key_list) == 0:
            return
        elif len(valid_key_list) != 0:
            if input(f"Message signed with revoked keys: {' '.join([key.name for key in revoked_key_list])}. Proceed anyways? [yN]\n").lower() != 'y':
                raise Git_PKI_Exception("Operation aborted by user.")
        else:
            raise Git_PKI_Exception(
                "Could not decrypt message signed with revoked key and message was signed after revocation time.")

    def import_keys(self, files):
        if not files:
            print("Paste the key and then press ctrl+d on an empty line")
            data = read_multiline_string()
            file = tempfile.mkstemp()[1]
            with open(file, "w") as output:
                output.write(data)
            files = [file]

        fingerprints = []
        imported = False
        for file in files:
            for fingerprint in self.__import_key(file):
                fingerprints.append(fingerprint)
                name = self.__gpg.public_key_name(fingerprint)
                file = f"{self.__git.identity_dir}/{name}/{fingerprint}"
                key = self.__gpg.export_public_key(fingerprint)
                self.__export_key(key, Path(file))
                imported = True

        if not imported:
            return
        branch_name = f'import/{sha1_encode("".join(fingerprints))}'
        message = f"Import keys {', '.join(fingerprints)}"
        self.__git.push_branch(branch_name, message)

    def export_keys(self, names, target_file, mode=None):
        if file_exists(target_file):
            if not mode:
                choices = ['append', 'cancel', 'overwrite']
                mode = iterfzf.iterfzf(choices, prompt=f"Output file: {target_file} already exists, select: <append> to add keys to the file, <overwrite> to remove existing file, or <cancel> to abort")
            if mode == 'overwrite':
                os.remove(target_file)
            if mode == 'cancel':
                return
        for name in names:
            key = self.__gpg.export_public_key(name)
            if not key:
                print(f"{name}: Failed\n")
            else:
                print(f"{name}:\n{key}\n")
                if target_file:
                    self.__export_key(key, Path(target_file))
                    print(f"{name}: exported to file: {target_file}")

    @staticmethod
    def __export_key(key, path):
        mkdir(path.parent)
        with open(path, "a") as file:
            file.write(key)

    def __import_key(self, path):
        if not file_exists(path):
            print(f"File {path} not found, aborting.")
            return []
        keys_from_file = self.__gpg.scan(path)
        if not keys_from_file:
            print(f"File {path} does not contain any key, aborting.")
            return []
        print(f"File {path} contains:")
        for key in keys_from_file:
            print(f"{key.fingerprint} key of {key.name} valid between {key.created_on} and {key.expires_on}")
        if input("is that OK? [yN] ").lower() != 'y':
            return []

        with open(path, 'rb') as file:
            imported = self.__gpg.import_public_key(file.read())

        successfully_imported_keys, is_import_successful = self.__get_successfully_imported_keys_and_status(imported)
        self.__print_import_summary(keys_from_file, imported)

        if not is_import_successful:
            print("\nThere were errors while importing keys, reverting changes.")
            self.remove_keys(successfully_imported_keys)
            keys_to_load = {key for key in keys_from_file if key.fingerprint in successfully_imported_keys}
            self.__load_keys_from_git(keys_to_load)
            return []

        return successfully_imported_keys

    @staticmethod
    def __print_import_summary(keys, imported_status):
        key_statuses = list(zip(keys, imported_status))
        succeded = [item for item in key_statuses if item[1]['ok'] == '1']
        unchanged = [item for item in key_statuses if item[1]['ok'] == '0' and item[1]['text'].endswith("Not actually changed\n")]
        failed = [key for key in key_statuses if key not in succeded and key not in unchanged]
        print("Import Summary:")
        if failed:
            print("\nFailed:")
            for fail in failed:
                print(f"{fail[1]['fingerprint']}, reason:  {fail[1]['text'].replace('Not actually changed', '').strip()}")
        if unchanged:
            print("\nUnchanged:")
            for unch in unchanged:
                print(format_key(unch[0]))
        if succeded:
            print("\nSucceded:")
            for succ in succeded:
                print(format_key(succ[0]))
        print('\n')

    @staticmethod
    def __get_successfully_imported_keys_and_status(imported_keys):
        import_successful = True
        successfully_imported = []
        for key_status in imported_keys:
            reason = key_status["text"]
            if key_status["ok"] == '0':
                if reason == 'Not actually changed\n':
                    continue
                import_successful = False
            else:
                successfully_imported.append(key_status['fingerprint'].lower())
        return successfully_imported, import_successful

    def __load_keys_from_git(self, key_list):
        backup_files = [self.__git.path_to(f"identity/{key.name}/{key.fingerprint}") for key in key_list]
        for file in backup_files:
            if file_exists(file):
                with open(file, "rb") as f:
                    self.__gpg.import_public_key(f.read())

    def remove_keys(self, fingerprint_list):
        for fingerprint in fingerprint_list:
            self.__gpg.remove_public_key(fingerprint)

    def review_requests(self):
        git = self.__git

        def map_change(change):
            if change.op == 'A':
                path = reviewed.path_to(change.path)
                return KeyChange(added=list(self.__gpg.scan(path)), removed=[])
            if change.op == 'R':
                path = git.path_to(change.path)
                return KeyChange(added=[], removed=list(self.__gpg.scan(path)))
            if change.op == 'M':
                removed = git.path_to(change.path)
                added = reviewed.path_to(change.path)
                return KeyChange(added, removed)

        self.merge_revoked()

        unmerged = list(git.list_branches_unmerged_to_remote_counterpart_of(git.current_branch()))
        if not unmerged:
            return
        for i, request in enumerate(unmerged):
            print(f"{i}) {request.title}")

        try:
            selected = int(input(f"Select request to review (0-{len(unmerged)-1}): "))
        except ValueError:
            raise Git_PKI_Exception("Please pass the integer value to select request.")

        request = git.get_request(unmerged[selected])
        if not git.is_mergeable_to('master', request.branch.full_name):
            print("Warning, cannot perform `git merge` automatically")

        changes = list(git.file_diff(request.branch.full_name))
        with git.open_worktree(self.__review_dir, request.branch.full_name) as reviewed:
            for change in map(map_change, changes):
                self.__run_checks(change, request, reviewed)
            print("Requested changes:")
            for change in map(map_change, changes):
                print(change)

        msg = 'Approve this changes? Answer "y" to merge them.'
        if input(msg).lower() != 'y':
            if input(f"\nDelete branch {request.branch} [yN] ?").lower() == 'y':
                git.remove_remote_branch(request.branch.name)
                print(f'\nSuccessfully deleted branch {request.branch}')
        else:
            self.merge_changes(request)

    def merge_changes(self, request):
        print(f'Merging branch {request.branch.name} into master...')
        self.__git.merge(request.branch.full_name)
        self.__git.push('master')
        self.__git.remove_remote_branch(request.branch.name)

    def merge_revoked(self):
        self.__git.fetch()
        self.__git.pull('master')
        unmerged_branches = list(self.__git.list_branches_unmerged_to_remote_counterpart_of(self.__git.current_branch()))
        for branch in unmerged_branches:
            request = self.__git.get_request(branch)
            if isinstance(request, RevokeIdentityRequest):
                if self.__git.is_mergeable_to('master', request.branch.full_name):
                    self.merge_changes(request)
                    couterbranch_candidate = request.branch.full_name.replace('_revoked', '')
                    try:
                        self.__git.merge(couterbranch_candidate)
                    except EnvironmentError:
                        pass
                else:
                    print(f"Error: Cannot automerge branch {request.branch.name}")

    def is_key_expired(self, key):
        if not key:
            return True
        if key.expires_on is None:
            return False
        return datetime.now() > datetime.strptime(key.expires_on, "%Y-%m-%d")

    def is_any_key_valid(self, path):
        for key in self.__gpg.scan(path):
            if not self.is_key_expired(key):
                return True
        return False

    def does_fingerprint_match_file(self, path):
        key = self.__gpg.scan(path)
        if not key:
            return False
        else:
            return str(path).endswith(key[0].fingerprint)

    def __run_checks(self, change, request, reviewed):
        if isinstance(request, ImportRequest):
            name = change.added[0].name if change.added else change.removed[0].name
            fingerprint = change.added[0].fingerprint if change.added else change.removed[0].fingerprint
        else:
            name = request.name
            fingerprint = request.fingerprint
        filepath = reviewed.path_to(os.path.join('identities', name, fingerprint))
        if not self.does_fingerprint_match_file(filepath):
            raise Git_PKI_Exception('File name and fingerprint are no equal.')
        if not self.is_any_key_valid(filepath):
            raise Git_PKI_Exception(f"The file {filepath} does not contain any valid key, aborting.")

    def is_key_revoked(self, key):
        return os.path.isfile(self.__git.path_to(os.path.join('identities', key.name, key.fingerprint + '_revoked')))

    def get_revocation_time(self, key):
        path = self.__git.path_to(os.path.join('identities', key.name, key.fingerprint + '_revoked'))
        if os.path.isfile(path):
            with open(path, 'r') as revoke_file:
                return datetime.strptime(revoke_file.read().strip(), '%Y-%m-%d %H:%M:%S%z')
        else:
            return datetime.strptime('2000-01-01 00:00:00+00:00', '%Y-%m-%d %H:%M:%S%z')

    def update(self):
        self.__git.pull('master')

        for root, dirs, files in os.walk(os.path.join(self.__git.root_dir, 'identities')):
            for file in files:
                if "revoke" in file:
                    continue
                identity_path = os.path.join(root, file)
                with open(identity_path, "rb") as f:
                    self.__gpg.import_public_key(f.read())
                if gpg_wrapper.verbose:
                    print(f"Loaded key: name: {os.path.dirname(identity_path).split('/')[-1]}, fingerprint: {file}")
        print("Successfully loaded all valid keys.")


def create_gpki_parser():
    common_args_parser = argparse.ArgumentParser(
        prog='git pki', argument_default=argparse.SUPPRESS, add_help=False)
    common_args_parser.add_argument('-h', '--help')
    common_args_parser.add_argument(
        '--version', '-v', action='version', version=f'%(prog)s version {__version__}')
    common_args_parser.add_argument('--verbose', action='store_true', default=False)

    cli_parser = argparse.ArgumentParser(
        prog='git pki',
        argument_default=argparse.SUPPRESS,
        add_help=False,
        parents=[common_args_parser]
    )

    subparsers = cli_parser.add_subparsers(dest='command')

    encrypt_parser = subparsers.add_parser(
        'encrypt',
        argument_default=argparse.SUPPRESS,
        usage=argparse.SUPPRESS,
        add_help=False,
        parents=[common_args_parser])
    encrypt_parser.add_argument('--input', '-i', default=None)
    encrypt_parser.add_argument('--output', '-o', default=None)
    encrypt_parser.add_argument('--password', '-p', default=None)
    encrypt_parser.add_argument('--all', '-a', action='store_true', default=False)

    decrypt_parser = subparsers.add_parser(
        'decrypt',
        argument_default=argparse.SUPPRESS,
        usage=argparse.SUPPRESS,
        add_help=False,
        parents=[common_args_parser])
    decrypt_parser.add_argument('--input', '-i', default=None)
    decrypt_parser.add_argument('--output', '-o', default=None)
    decrypt_parser.add_argument('--password', '-p', default=None)
    decrypt_parser.add_argument('--update', '-u', action='store_true', default=False)

    new_identity_parser = subparsers.add_parser(
        'identity',
        argument_default=argparse.SUPPRESS,
        usage=argparse.SUPPRESS,
        add_help=False,
        parents=[common_args_parser])
    new_identity_parser.add_argument('name', nargs='?')
    new_identity_parser.add_argument('--email', default=None)
    new_identity_parser.add_argument('--description', default=None)

    import_key_parser = subparsers.add_parser(
        'import',
        argument_default=argparse.SUPPRESS,
        usage=argparse.SUPPRESS,
        add_help=False,
        parents=[common_args_parser])
    import_key_parser.add_argument('--input', '-i', nargs='+', default=None)

    export_key_parser = subparsers.add_parser(
        'export',
        argument_default=argparse.SUPPRESS,
        usage=argparse.SUPPRESS,
        add_help=False,
        parents=[common_args_parser])
    export_key_parser.add_argument('key_names', nargs='+')
    export_key_parser.add_argument('--output', '-o', default=None)

    subparsers.add_parser(
        'recipients',
        argument_default=argparse.SUPPRESS,
        usage=argparse.SUPPRESS,
        add_help=False,
        parents=[common_args_parser])

    subparsers.add_parser(
        'signatories',
        argument_default=argparse.SUPPRESS,
        usage=argparse.SUPPRESS,
        add_help=False,
        parents=[common_args_parser])

    subparsers.add_parser(
        'review',
        argument_default=argparse.SUPPRESS,
        usage=argparse.SUPPRESS,
        add_help=False,
        parents=[common_args_parser])

    subparsers.add_parser(
        'update',
        argument_default=argparse.SUPPRESS,
        usage=argparse.SUPPRESS,
        add_help=False,
        parents=[common_args_parser])

    subparsers.add_parser(
        'revoke',
        argument_default=argparse.SUPPRESS,
        usage=argparse.SUPPRESS,
        add_help=False,
        parents=[common_args_parser])

    return cli_parser


def launch(parsed_cli):
    gpg_wrapper.verbose = parsed_cli.verbose

    gpki = GPKI("/tmp/foobarbaz")
    cmd = parsed_cli.command

    if cmd == 'decrypt':
        gpki.decrypt(parsed_cli.input, parsed_cli.output, parsed_cli.password, parsed_cli.update)
    elif cmd == 'encrypt':
        gpki.encrypt(parsed_cli.input, parsed_cli.output, parsed_cli.password, parsed_cli.all)
    elif cmd == 'identity':
        if 'name' not in parsed_cli:
            raise Git_PKI_Exception("Name is mandatory while creating new identity.")
        gpki.generate_identity(parsed_cli.name, parsed_cli.email, parsed_cli.description)
    elif cmd == 'import':
        gpki.import_keys(parsed_cli.input)
    elif cmd == 'export':
        gpki.export_keys(parsed_cli.key_names, parsed_cli.output)
    elif cmd == 'recipients':
        gpki.list_recipients()
    elif cmd == 'signatories':
        gpki.list_signatories()
    elif cmd == 'review':
        gpki.review_requests()
    elif cmd == 'update':
        gpki.update()
    elif cmd == 'revoke':
        gpki.revoke()
    else:
        # Some help should be printed here
        raise Git_PKI_Exception(f"Command {cmd} is not a valid git-pki command.")


def main():
    args = sys.argv[1:]
    cli_parser: argparse.ArgumentParser = create_gpki_parser()
    parsed_cli = cli_parser.parse_args(args)
    launch(parsed_cli)


if __name__ == "__main__":
    main()

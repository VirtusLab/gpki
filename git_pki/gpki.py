#!/usr/local/bin/python3
import argparse
import os
import sys
import tempfile

import getpass
import iterfzf
from pathlib import Path

from git_pki import __version__
from git_pki.custom_types import KeyChange
from git_pki.exceptions import Git_PKI_Exception
from git_pki.git_wrapper import Git
from git_pki.gpg_wrapper import GnuPGHandler
from git_pki.utils import does_file_exist, format_key, get_file_list, mkdir, read_multiline_string
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
        self.__gpg = GnuPGHandler(self.__file_gpghome)
        self.__git = Git(self.__file_repository)

        listener = KeyChangeListener(self.__gpg)
        self.__git.update(listener)

    def generate_identity(self, name, email, description, passphrase=None):
        # TODO (#22): verify that repository is in clean state? are we on master branch?
        existing_key = self.__gpg.private_key_fingerprint(name)
        if existing_key is not None:
            # If key exists, confirm removal of the private version and move public one to the archive
            response = input(f"Replace existing identity of {existing_key}? [yN] ")
            if response.lower() != "y":
                return
            passphrase = getpass.getpass(f"Specify passphrase for the existing key of [{name}]: ")
            self.__gpg.remove_private_key(existing_key, passphrase)
            # TODO (#23): ask to set private/public key to expired state
            #  if so, publish updated public key
        fingerprint = self.__gpg.generate_key(name, email, description, passphrase=passphrase)
        if fingerprint is None:
            return

        key = self.__gpg.export_public_key(name)
        file = Path(f"{self.__git.identity_dir}/{name}/${fingerprint}")
        self.__export_key(key, Path(file))
        self.__git.push(f"{name}/{fingerprint}", f"Publish key {name}/{fingerprint}")
        print(key)
        # TODO (#24): maybe find a way to revert changes if PR gets rejected ?
        #  fetch --prune, then check which branch is present locally and not on remote, then remove keys from selected branches

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

    def encrypt(self, source, target, passphrase=None):
        if target is not None and os.path.isfile(target):
            if input(f"Target file already exist, do you want to overwrite? [yN] ").lower() != 'y':
                return
        available_recipients = map(format_key, self.__gpg.public_keys_list())
        selection = iterfzf.iterfzf(available_recipients, prompt="Select recipient: ")
        if selection is None:
            return
        recipient = selection.split()[0]

        available_signatories = map(format_key, self.__gpg.private_keys_list())
        selection = iterfzf.iterfzf(available_signatories, prompt="Select signatory or press ctrl+d to not sign ")
        signatory = None if selection is None else selection.split()[0]

        if not passphrase:
            passphrase = getpass.getpass(f"Specify passphrase for [{selection[0]}]: ")

        self.__gpg.encrypt(recipient, signatory, source, target, passphrase)

    def decrypt(self, source, target, passphrase=None):
        if does_file_exist(target):
            if input(f"Target file already exist, do you want to overwrite? [yN] ").lower() != 'y':
                return

        if source is None:
            data = []
            print("Paste message, then press enter and ctrl+d")
            for line in sys.stdin:
                data.append(line)
            source = "".join(data)
            recipient = self.__gpg.get_recipients_from_message(source)
        elif os.path.isfile(source):
            with open(source, 'rb') as src_file:
                recipient = self.__gpg.get_recipients_from_file(src_file)
        else:
            print(f"Specified source file: {source} was not found, aborting.")
            return
        if not passphrase:
            passphrase = getpass.getpass(f"Specify passphrase for {recipient}: ")
        self.__gpg.decrypt(source, target, passphrase)

    def import_keys(self, files):
        if not files:
            print("Paste the key and then press ctrl+d on an empty line")
            data = read_multiline_string()
            file = tempfile.mkstemp()[1]
            with open(file, "w") as output:
                output.write(data)
            files = [file]

        imported = False
        for file in files:
            for fingerprint in self.__import_key(file):
                name = self.__gpg.public_key_name(fingerprint)
                file = f"{self.__git.identity_dir}/{name}/{fingerprint}"
                key = self.__gpg.export_public_key(fingerprint)
                self.__export_key(key, Path(file))
                imported = True

        if not imported:
            return
        branch = input("Specify branch name: ").replace(" ", "_")
        message = input("Specify commit title: ")
        self.__git.push(branch, message)

    def export_keys(self, names, target_file, mode=None):
        if does_file_exist(target_file):
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
        if not does_file_exist(path):
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
            self.remove_keys([key['fingerprint'] for key in successfully_imported_keys])
            self.__load_keys_from_git(successfully_imported_keys)
            return []

        return list(map(lambda x: x["fingerprint"].lower(), successfully_imported_keys))

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
                successfully_imported.append(key_status)
        return successfully_imported, import_successful

    def __load_keys_from_git(self, key_list):
        fingerprint_list = [key['fingerprint'].lower() for key in key_list]
        for fprint in fingerprint_list:
            for file in get_file_list(self.__file_repository):
                if file.endswith(fprint):
                    with open(file, "rb") as f:
                        self.__gpg.import_public_key(f.read())

    def remove_keys(self, fingerprint_list):
        for fingerprint in fingerprint_list:
            self.__gpg.remove_public_key(fingerprint)

    def review_requests(self):
        unmerged = list(self.__git.list_branches_unmerged_to_remote_counterpart_of(self.__git.current_branch()))
        if not unmerged:
            return
        for i, request in enumerate(unmerged):
            print(f"{i}) {request.title}")

        selected = int(input(f"Select request to review (0-{len(unmerged)}): "))
        request = unmerged[selected]  # TODO (#29): verify if key added in PR is valid, extract fingerprint from branch_name

        print("Requested changes:")
        changes = self.__git.file_diff(request.branch)
        reviewed = self.__git.open_worktree(self.__review_dir, request.branch)
        try:   # TODO (#30): Check if Try still needed after implementation
            def map_change(change):
                if change.op == 'A':
                    path = reviewed.path_to(change.path)
                    return KeyChange(added=list(self.__gpg.scan(path)), removed=[])
                if change.op == 'R':
                    path = self.__git.path_to(change.path)
                    return KeyChange(added=[], removed=list(self.__gpg.scan(path)))
                if change.op == 'M':
                    removed = self.__git.path_to(change.path)
                    added = reviewed.path_to(change.path)
                    return KeyChange(added, removed)
                # TODO (#31): also compare file name with its fingerprint (extract to method)
            for x in map(map_change, changes):
                print(x)
            # TODO (#32):  accept / reject (also confirm)
            #  ask if accept/reject, accept => merge and push, reject => ask to remove branch
        finally:
            self.__git.close_worktree(request.branch)


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

    decrypt_parser = subparsers.add_parser(
        'decrypt',
        argument_default=argparse.SUPPRESS,
        usage=argparse.SUPPRESS,
        add_help=False,
        parents=[common_args_parser])
    decrypt_parser.add_argument('--input', '-i', default=None)
    decrypt_parser.add_argument('--output', '-o', default=None)
    decrypt_parser.add_argument('--password', '-p', default=None)

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

    return cli_parser


def launch(parsed_cli):
    gpg_wrapper.verbose = parsed_cli.verbose

    gpki = GPKI("/tmp/foobarbaz")

    cmd = parsed_cli.command

    if cmd == 'decrypt':
        gpki.decrypt(parsed_cli.input, parsed_cli.output, parsed_cli.password)
    elif cmd == 'encrypt':
        gpki.encrypt(parsed_cli.input, parsed_cli.output, parsed_cli.password)
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

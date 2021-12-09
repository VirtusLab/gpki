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
from git_pki.utils import format_key, mkdir, read_multiline_string


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
        # TODO (#35): Allow to decrypt from and to file
        if not passphrase:
            if source is not None and os.path.isfile(source):
                with open(source, 'rb') as src_file:
                    recipient = self.__gpg.get_recipient(src_file)
            else:
                data = []
                print("Paste message, then press enter and ctrl+d")
                for line in sys.stdin:
                    data.append(line)
                source = "".join(data)
                recipient = self.__gpg.get_recipient(source)
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

    def export_keys(self, names):
        for name in names:
            key = self.__gpg.export_public_key(name)
            if not key:
                print(f"{name}: Failed\n")
            else:
                print(f"{name}:\n{key}\n")

    @staticmethod
    def __export_key(key, path):
        mkdir(path.parent)
        with open(path, "w") as file:
            file.write(key)

    def __import_key(self, path):
        keys = self.__gpg.scan(path)
        print(f"File {path} contains:")  # TODO (#26): when we fail to import any key from a file, we should remove all keys from this file
        for key in keys:
            print(f"{key.fingerprint} key of {key.name} valid between {key.created_on} and {key.expires_on}")
        if input("is that OK? [yN] ").lower() != 'y':
            return []

        with open(path, "rb") as file:
            imported = self.__gpg.import_public_key(file.read())

        if not imported:
            return []
        mkdir(f"{self.__git.identity_dir}")  # I don't really want to repeat that every goddamn time...
        for status in imported:
            fingerprint = status["fingerprint"].lower()
            reason = status["text"]
            if status["ok"] is None:
                print(f"Failed to import {fingerprint} due to: {reason}")
            else:  # TODO (#27): do not print out unchanged keys
                print(f"Imported: {fingerprint}. {reason}")

        # TODO (#28): do not return fingerprints of the unchanged keys
        return map(lambda x: x["fingerprint"].lower(), imported)

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


def cmd_encrypt(gpki, args):
    if len(args) == 0:
        gpki.encrypt(None, None)
    elif len(args) == 1:
        path = Path(args[0])
        if path.is_file():
            gpki.encrypt(source=path, target=None)
        else:
            gpki.encrypt(source=None, target=path)
    else:
        source = Path(args[0])
        target = Path(args[1])
        if not source.is_file():
            raise Exception(f"Not a file: {source}")
        if target.is_file():
            pass  # TODO (#33): ask to overwrite
        gpki.encrypt(source, target)


def create_gpki_parser():
    common_args_parser = argparse.ArgumentParser(
        prog='git pki', argument_default=argparse.SUPPRESS, add_help=False)
    common_args_parser.add_argument('-h', '--help')
    common_args_parser.add_argument(
        '--version', action='version', version=f'%(prog)s version {__version__}')
    common_args_parser.add_argument('-v', '--verbose', action='store_true')

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
    encrypt_parser.add_argument('--source', '-s', default=None)
    encrypt_parser.add_argument('--target', '-t', default=None)
    encrypt_parser.add_argument('--passphrase', '-p', default=None)

    decrypt_parser = subparsers.add_parser(
        'decrypt',
        argument_default=argparse.SUPPRESS,
        usage=argparse.SUPPRESS,
        add_help=False,
        parents=[common_args_parser])
    decrypt_parser.add_argument('--source', '-s', default=None)
    decrypt_parser.add_argument('--target', '-t', default=None)
    decrypt_parser.add_argument('--passphrase', '-p', default=None)

    new_identity_parser = subparsers.add_parser(
        'new_identity',
        argument_default=argparse.SUPPRESS,
        usage=argparse.SUPPRESS,
        add_help=False,
        parents=[common_args_parser])
    new_identity_parser.add_argument('name', nargs='?')
    new_identity_parser.add_argument('--email', default=None)
    new_identity_parser.add_argument('--description', default=None)

    import_key_parser = subparsers.add_parser(
        'import_key',
        argument_default=argparse.SUPPRESS,
        usage=argparse.SUPPRESS,
        add_help=False,
        parents=[common_args_parser])
    import_key_parser.add_argument('source_file', nargs='?')

    export_key_parser = subparsers.add_parser(
        'export_key',
        argument_default=argparse.SUPPRESS,
        usage=argparse.SUPPRESS,
        add_help=False,
        parents=[common_args_parser])
    export_key_parser.add_argument('key_names', nargs='+')

    subparsers.add_parser(
        'list_recipients',
        argument_default=argparse.SUPPRESS,
        usage=argparse.SUPPRESS,
        add_help=False,
        parents=[common_args_parser])

    subparsers.add_parser(
        'list_signatory',
        argument_default=argparse.SUPPRESS,
        usage=argparse.SUPPRESS,
        add_help=False,
        parents=[common_args_parser])

    subparsers.add_parser(
        'request_review',
        argument_default=argparse.SUPPRESS,
        usage=argparse.SUPPRESS,
        add_help=False,
        parents=[common_args_parser])

    return cli_parser


def launch(parsed_cli, gpki):
    cmd = parsed_cli.command

    if cmd == 'decrypt':
        gpki.decrypt(parsed_cli.source, parsed_cli.target, parsed_cli.passphrase)
    elif cmd == 'encrypt':
        gpki.encrypt(parsed_cli.source, parsed_cli.target, passphrase=parsed_cli.passphrase)
    elif cmd == 'new_identity':
        if 'name' not in parsed_cli:
            raise Git_PKI_Exception("Name is mandatory while creating new identity.")
        gpki.generate_identity(parsed_cli.name, parsed_cli.email, parsed_cli.description)
    elif cmd == 'import_key':
        if 'source_file' not in parsed_cli:
            raise Git_PKI_Exception("Please specify a filename to import keys from.")
        gpki.import_keys(parsed_cli.key_names)
    elif cmd == 'export_key':
        gpki.export_keys(parsed_cli.key_names)
    elif cmd == 'list_recipients':
        gpki.list_recipients()
    elif cmd == 'list_signatory':
        gpki.list_signatories()
    elif cmd == 'request_review':
        gpki.review_requests()
    else:
        # Some help should be printed here
        raise Git_PKI_Exception(f"Command {cmd} is not a valid git-pki command.")


def main():
    args = sys.argv[1:]
    gpki = GPKI("/tmp/foobarbaz")
    cli_parser: argparse.ArgumentParser = create_gpki_parser()
    parsed_cli = cli_parser.parse_args(args)
    launch(parsed_cli, gpki)


if __name__ == "__main__":
    main()

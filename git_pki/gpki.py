#!/usr/local/bin/python3
import sys
import tempfile

from getpass import getpass
from iterfzf import iterfzf
from pathlib import Path

from git_pki.custom_types import KeyChange
from git_pki.git_wrapper import Git
from git_pki.gpg_wrapper import GnuPGHandler
from git_pki.utils import mkdir, read_multiline_string


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

    def generate_identity(self, name, email, description):
        # TODO verify that repository is in clean state?
        existing_key = self.__gpg.private_key_fingerprint(name)
        if existing_key is not None:
            # If key exists, confirm removal of the private version and move public one to the archive
            response = input(f"Replace existing identity of {existing_key}? [yN] ")
            if response.lower() != "y":
                return
            passphrase = getpass(f"Specify passphrase for the existing key of [{name}]: ")
            self.__gpg.remove_private_key(existing_key, passphrase)
            # TODO what with public key? I think we should keep it until revoked / expired
            #  maybe asking if it should be revoked also?

        fingerprint = self.__gpg.generate_key(name, email, description)
        if fingerprint is None:
            return

        key = self.__gpg.export_public_key(name)
        file = Path(f"{self.__git.identity_dir}/{name}/${fingerprint}")
        self.__export_key(key, Path(file))
        # TODO is it a good branch name? It allows multiple choices for someone to choose from
        #   but also allows for semi-automated verification, approval and rejection
        self.__git.push(f"{name}/{fingerprint}", f"Publish key {name}/{fingerprint}")
        print(key)
        # TODO maybe find a way to revert changes if PR gets rejected ?

    def list_signatories(self):
        print("fingerprint                              created-on expires-on\tidentity\temail\tdescription")
        for key in self.__gpg.private_keys_list():
            # TODO no idea how to align those nicely
            print(f"{key}")

    def list_recipients(self):
        print("fingerprint                              created-on expires-on\tidentity\temail\tdescription")
        for key in self.__gpg.public_keys_list():
            # TODO no idea how to align those nicely
            print(f"{key}")

    def encrypt(self, source, target):
        f = lambda key: f"{key.fingerprint} {key.created_on} {key.expires_on} {key.name} {key.email} {key.description}"
        available_recipients = map(f, self.__gpg.public_keys_list())
        selection = iterfzf(available_recipients, prompt="Select recipient: ")
        if selection is None:
            return
        recipient = selection.split()[0]

        available_signatories = map(f, self.__gpg.private_keys_list())
        selection = iterfzf(available_signatories, prompt="Select signatory or press ctrl+d to not sign ")
        signatory = None if selection else selection.split()[0]

        passphrase = getpass(f"Specify passphrase for [{selection[0]}]: ")

        self.__gpg.encrypt(recipient, signatory, source, target, passphrase)

    def decrypt(self, source, target):
        self.__gpg.decrypt(source, target)

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
        print(f"File {path} contains:")
        for key in keys:
            print(f"{key.fingerprint} key of {key.name} valid between {key.created_on} and {key.expires_on}")  # TODO we should treat importing single file a'la transcation
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
            else:  # TODO can special-case unchanged keys (e.g. don't print or print "Unchanged {fingerprint}" ?)
                print(f"Imported: {fingerprint}. {reason}")

        # TODO should probably not return fingerprints of the unchanged keys
        return map(lambda x: x["fingerprint"].lower(), imported)

    def review_requests(self):
        unmerged = list(self.__git.list_branches_unmerged_to_remote_counterpart_of(self.__git.current_branch()))
        if not unmerged:
            return
        for i, request in enumerate(unmerged):
            print(f"{i}) {request.title}")

        selected = int(input(f"Select request to review (0-{len(unmerged)}): "))
        request = unmerged[selected]  # TODO more checks

        print("Requested changes:")
        changes = self.__git.file_diff(request.branch)
        reviewed = self.__git.open_worktree(self.__review_dir, request.branch)
        try:
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
                # TODO also compare file name with its fingerprint
            for x in map(map_change, changes):
                print(x)
            # TODO decide: accept / review (also confirm)
        finally:
            self.__git.close_worktree(request.branch)


def cmd_identity_generate(gpki, args):
    name = args[0] if args else input("Specify name (required): ")
    email = input("Specify email (optional): ")
    descr = input("Specify description (optional): ")
    gpki.generate_identity(name, email, descr)


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
            pass  # TODO ask to overwrite
        gpki.encrypt(source, target)


def dispatch(gpki, args, routes):
    route = routes[args[0]]
    if isinstance(route, dict):
        dispatch(gpki, args[1:], route)
    elif callable(route):
        route(gpki, args[1:])
    else:
        raise Exception(f"Unsupported route: {route}")


routes = {
    "decrypt": lambda gpki, args: gpki.decrypt(None, None),
    "encrypt": cmd_encrypt,
    "new": cmd_identity_generate,
    "key": {
        "import": lambda gpki, files: gpki.import_keys(files),
        "export": lambda gpki, names: gpki.export_keys(names)
    },
    "recipient": {
        "list": lambda gpki, args: gpki.list_recipients()
    },
    "request": {
        "review": lambda gpki, args: gpki.review_requests()
    },
    "signatory": {
        "list": lambda gpki, args: gpki.list_signatories()
    }
}


def main():
    args = sys.argv[1:]
    gpki = GPKI("/tmp/foobarbaz")
    dispatch(gpki, args, routes)


if __name__ == "__main__":
    main()


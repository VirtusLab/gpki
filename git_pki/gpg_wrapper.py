
import gnupg
import os
import sys

from getpass import getpass
from datetime import datetime

from git_pki.custom_types import Key


verbose = False


class GnuPGHandler:
    def __init__(self, gnupghome):
        self.gpg = gnupg.GPG(gnupghome=gnupghome, options=['--yes', '--pinentry-mode', 'loopback'], verbose=verbose)
        self.gpg.encoding = 'utf-8'

    def generate_key(self, name, email, description, passphrase=None):
        key_spec = f"""
                   Key-Type:	RSA
                   Key-Length: 	3072
                   Name-Real: 	{name}
                   {f'Name-Email: 	{email}' if email else ''}
                   {f'Name-Comment:{description}' if description else ''}
                   Expire-Date:	6m
                   Passphrase: 	{passphrase if passphrase else getpass("New key passphrase: ")}
                    """

        return self.gpg.gen_key(key_spec).fingerprint.lower()

    def export_public_key(self, name):
        return self.gpg.export_keys(name)

    def import_public_key(self, armored):
        if verbose:
            print(f"Importing {armored}")
        return self.gpg.import_keys(armored).results

    def private_keys_list(self):
        keys = self.gpg.list_keys(True)
        return map(self.parse_key, keys)

    def private_key_fingerprint(self, name):
        keys = self.gpg.list_keys(True, keys=name)
        return keys[0]["fingerprint"].lower() if keys else None

    def public_keys_list(self, names=None):
        keys = self.gpg.list_keys(False, keys=names)
        return map(self.parse_key, keys)

    def public_key_name(self, fingerprint):
        keys = self.gpg.list_keys(False, keys=fingerprint)
        return keys[0]["uids"][0] if keys else None

    def public_key_fingerprint(self, name):
        keys = self.gpg.list_keys(False, keys=name)
        return keys[0]["fingerprint"].lower() if keys else None

    def file_key_fingerprint(self, path):
        keys = self.gpg.scan_keys(path)
        return keys[0]["fingerprint"] if keys else None

    def remove_private_key(self, fingerprint, passphrase):
        self.gpg.delete_keys(fingerprint, True, passphrase=passphrase)

    def remove_public_key(self, fingerprint):
        self.gpg.delete_keys(fingerprint, False)

    def encrypt(self, recipient, signatory, source, target, passphrase):
        if source is None:
            data = []
            print("Write message, then press enter and ctrl+d")
            for line in sys.stdin:
                data.append(line)
            result = self.gpg.encrypt("".join(data), recipient, sign=signatory, output=target, passphrase=passphrase)
        elif os.path.isfile(source):
            with open(source, "rb") as data:
                result = self.gpg.encrypt_file(data, recipient, sign=signatory, output=target, passphrase=passphrase)
        else:
            print(f"Specified source file: {source} was not found, aborting.")
        if not result.ok:
            print(f"Could not encrypt: {result.status}. Was passphrase correct?")
            return
        if target is None:
            print(result)
        else:
            print(f"Encrypted data saved in {target}")

    def decrypt(self, source, target, passphrase):
        if os.path.isfile(source):
            with open(source, "rb") as source_file:
                result = self.gpg.decrypt_file(source_file, output=target, passphrase=passphrase)
        else:
            result = self.gpg.decrypt("".join(source), output=target, passphrase=passphrase)
        if not result.ok:
            print(f"Could not decrypt: {result.status}. Was passphrase correct?")
            return
        if target is None:
            print(result)
        else:
            print(f"Decrypted data saved in {target}")

    def get_recipients_from_file(self, source_file):
        return self.gpg.get_recipients_file(source_file)

    def get_recipients_from_message(self, message):
        return self.gpg.get_recipients(message)

    def scan(self, file):
        keys = self.gpg.scan_keys(file)
        return list(map(self.parse_key, keys))

    def parse_key(self, raw_key):
        uid = raw_key["uids"][0]
        name = uid.split()[0]
        email = None if name == uid else uid.split()[1][1:-1]
        description = None if name == uid else uid.split()[2][1:-1]
        fingerprint = raw_key["fingerprint"].lower()
        created_on = self.__key_parse_date(raw_key, "date")
        expires_on = self.__key_parse_date(raw_key, "expires")
        return Key(name, email, description, fingerprint, created_on, expires_on)

    @staticmethod
    def __key_parse_date(key, field):
        try:
            return datetime.fromtimestamp(int(key[field])).strftime("%Y-%m-%d")
        except ValueError:
            return None  # in case there is no expiration date

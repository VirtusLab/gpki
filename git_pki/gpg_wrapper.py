
import gnupg
import os
import sys

from getpass import getpass
from datetime import datetime
from collections.abc import Iterable

from git_pki.custom_types import Key, SignatureVerification
from git_pki.utils import is_string


verbose = True


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

    def private_keys_list(self, names=None):
        keys = self.gpg.list_keys(True)
        keys = filter(lambda key: self.__raw_key_matches(key, names), keys)
        return map(self.parse_key, keys)

    def private_key_fingerprint(self, name):
        keys = self.private_keys_list(name)
        key = next(keys, None)
        return None if key == None else key.fingerprint

    def public_keys_list(self, names=None):
        keys = self.gpg.list_keys(False)
        keys = filter(lambda key: self.__raw_key_matches(key, names), keys)
        return map(self.parse_key, keys)

    def public_key_name(self, fingerprint):
        keys = self.public_keys_list(fingerprint)
        key = next(keys, None)
        return None if key == None else key.name

    def public_key_fingerprint(self, name):
        keys = self.public_keys_list(name)
        key = next(keys, None)
        return None if key == None else key.fingerprint

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
            result = self.gpg.encrypt("".join(data), recipient, sign=signatory, output=target, passphrase=passphrase, always_trust=True)
        elif os.path.isfile(source):
            with open(source, "rb") as data:
                result = self.gpg.encrypt_file(data, recipient, sign=signatory, output=target, passphrase=passphrase, always_trust=True)
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

    def verify_signature(self, source, passphrase):
        if os.path.isfile(source):
            with open(source, "rb") as source_file:
                result = self.gpg.decrypt_file(source_file, output=None, passphrase=passphrase)
        else:
            result = self.gpg.decrypt("".join(source), output=None, passphrase=passphrase)

        if not result.ok:
            print(f"Could not verify: {result.status}.")
            return

        return self.parse_verification(result.sig_info)

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
    def parse_verification(sig_info):
        signatories = []
        for sig_hash in sig_info.keys():
            timestamp = sig_info[sig_hash]['timestamp']
            signatory_fingerprint = sig_info[sig_hash]['fingerprint'].lower()
            signatory_name = sig_info[sig_hash]['username']
            expiry = sig_info[sig_hash]['expiry']
            status = sig_info[sig_hash]['status']
            signatories.append(SignatureVerification(timestamp, signatory_fingerprint, signatory_name, expiry, status))
        return signatories

    @staticmethod
    def __key_parse_date(key, field):
        try:
            return datetime.fromtimestamp(int(key[field])).strftime("%Y-%m-%d")
        except ValueError:
            return None  # in case there is no expiration date

    def get_private_key_by_id(self, keyid):
        keys = self.private_keys_list(keyid)
        return next(keys, None)

    def get_public_key_by_id(self, keyid):
        keys = self.public_keys_list(keyid)
        return next(keys, None)

    def __raw_key_matches(self, key, names) -> bool:
        if names == None:
            return True
        if is_string(names):
            names = [names]

        for name in names:
            if key["fingerprint"].lower() == name:
                return True
            for uid in key["uids"]:
                if uid.split()[0] == name:
                    return True
        return False
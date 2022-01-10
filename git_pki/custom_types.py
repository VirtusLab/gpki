from collections import namedtuple
from typing import NewType

new_line = '\n '
PREVIOUS_BRANCH = '-'

ShellCommand = NewType("ShellCommand", str)

Branch = namedtuple('Branch', ['remote', 'name', 'full_name'])
Request = namedtuple('Request', ["branch", "title"])
FileChange = namedtuple('FileChange', ["op", "path"])
Key = namedtuple('Key', ["name", "email", "description", "fingerprint", "created_on", "expires_on"])
AddIdentityRequest = namedtuple('AddIdentityRequest', ['branch', 'name', 'fingerprint', 'file'])
RevokeIdentityRequest = namedtuple('RevokeIdentityRequest', ['branch', 'name', 'fingerprint', 'file'])
ImportRequest = namedtuple('ImportRequest', ['branch', 'hash'])


class KeyChange:
    def __init__(self, added, removed):
        self.added = added
        self.removed = removed

    def __str__(self):
        return (f"Added:\n {new_line.join(str(item) for item in self.added)}\n" if self.added else ""
                f"Removed:\n {new_line.join(str(item) for item in self.removed)}\n" if self.removed else "")

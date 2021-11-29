from collections import namedtuple
from typing import NewType


ShellCommand = NewType("ShellCommand", str)

Request = namedtuple('Request', ["branch", "title"])
FileChange = namedtuple('FileChange', ["op", "path"])
KeyChange = namedtuple('KeyChange', ["added", "removed"])
Key = namedtuple('Key', ["name", "email", "description", "fingerprint", "created_on", "expires_on"])

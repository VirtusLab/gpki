import logging
import os
import subprocess
import sys

from hashlib import sha1
from time import time_ns

from git_pki.custom_types import ShellCommand

def is_string(value) -> bool:
    return isinstance(value, str)

def read_multiline_string(prompt=None):
    if prompt:
        print(prompt)
    lines = []
    for line in sys.stdin:
        lines.append(line)
    return "".join(lines)


def mkdir(name, mode=None):
    if not mode:
        os.makedirs(name, exist_ok=True)
    else:
        os.makedirs(name, mode, exist_ok=True)
    return name


def file_exists(file_path):
    return file_path is not None and os.path.isfile(file_path)


def shell(cwd, command: ShellCommand) -> str:
    logging.debug(command)
    proc = subprocess.run(command, cwd=cwd, shell=True, capture_output=True)
    if proc.returncode == 0:
        return proc.stdout.decode("utf-8")
    else:
        raise EnvironmentError(
            f"The command [{command}]\nfailed with return code {proc.returncode}.\n"
            f"stderr:\n{proc.stderr.decode('utf-8')}")


def format_key(key):
    return f"{key.fingerprint} {key.created_on} {key.expires_on} {key.name} {key.email} {key.description}"


def sha1_encode(msg):
    msg = msg + str(time_ns())
    return sha1(msg.encode()).hexdigest()

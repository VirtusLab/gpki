import logging
import os
import subprocess
import sys

from typing import NewType


ShellCommand = NewType("ShellCommand", str)


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


def shell(cwd, command: ShellCommand) -> str:
    logging.debug(command)
    proc = subprocess.run(command, cwd=cwd, shell=True, capture_output=True)
    if proc.returncode == 0:
        return proc.stdout.decode("utf-8")
    else:
        raise EnvironmentError(
            f"The command [{command}]\nfailed with return code {proc.returncode}.\n"
            f"stderr:\n{proc.stderr.decode('utf-8')}")
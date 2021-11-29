#!/usr/bin/env python3

from git_pki import __version__
from os import path
from setuptools import setup

this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, 'README.md')) as f:
    long_description = f.read()

setup(
    name='git_pki',
    version=__version__,
    description='Git Public Key Infrastructure',
    long_description=long_description,
    long_description_content_type='text/markdown',
    packages=['git_pki'],
    scripts=['gpki'],
    python_requires='>=3.6',
    options={'bdist_wheel': {'universal': '1'}},
)



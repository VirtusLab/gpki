# Goal: Simple Public Key Infrastructure

By storing [Public Keys](https://en.wikipedia.org/wiki/Public-key_cryptography) in a version controlled storage (like
git), we can achieve a high level of automation in managing the network of trusted identities.

_GPKI_ is being designed to automate and simplify the management of such a network. It is responsible for:  
a) registering identities within the network  
b) encrypting and decrypting messages from the network members

## Design

_GPKI_ leverages both git and gpg to provide its functionality. The system consists of two parts: private vault and
public repository. Vault is a GPG keychain storing every private and public key while the public repository is where
only the public keys end up for other members to see.

### Identity

Every identity is a tuple of (name, email, description), where names should allow easy identification of its owner. It
is possible for any user to own multiple identities, which might be beneficial when contacting external entities or if
one needs to manually partition the network. Although in most cases a single identity should be enough.

### Where is the Certificate Authority?

The key network is as secure as the git repository hosting the public key infrastructure. New identities can only be added by the users with correct permissions,
hence there is no need for an explicit CA signing keys.

## Use Case

Sometimes, people need to share with another person a message, which they would like to keep confidential. With the help
of _GPKI_ it becomes as easy as installing it and maintaining a git repository (e.g. on github).

Examples might be: household/family networks or confidential team-members communication (e.g. sharing confidential
memos)

## Installation

_GPKI_ is based on Python, Git and GnuPG, so make sure to have following installed:
```
python >= 3.6
GnuPG >= 2.1
Git >= 2.3
```
Install _GPKI_ directly from repository with a few commands:
```
git clone git@github.com:VirtusLab/gpki.git
cd gpki
python3 -m pip install -r requirements.txt
python3 setup.py install --user
```

You are all set and ready to use _GPKI_ 

### Getting started
The prerequisite is having a dedicated git repository with appropriate security settings set up (i.e. only trusted users should be allowed to push changes to master branch).

When run for the first time, the user will be asked for a link to the git repository.
Every message is encrypted and signed by one of the locally created identities. 

To create one, use:

`gpki identity <name> [--email <email>] [--description <description>]`

This creates a public/private key pair in the local gpg vault and pushes a new branch with the public key to the repository for review.
It has to be approved (and merged) by one of the CAs to become visible to others.

To synchronize keyring with all available recipients from repository, use:

`gpki update`

Encrypt message or file with:

`gpki encrypt [--all/-a] [--input/-i <input_path>] [--output/-o <output_path>]`

When `input` is omitted, it will be read from standard input.
When `output` is omitted, it will be printed to the standard output.

Decrypt message with:

`gpki decrypt [--input/-i <input_path>] [--output/-o <output_path>] [--update/-u]`

When `input` is omitted, it will be read from standard input.
When `output` is omitted, it will be printed to the standard output.
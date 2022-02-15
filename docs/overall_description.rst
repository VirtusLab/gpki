.. _overall_description:

Goal: Simple Public Key Infrastructure
======================================

By storing `Public Keys`_  in a version controlled storage (like
git), we can achieve a high level of automation in managing the network of trusted identities.

.. _Public Keys: https://en.wikipedia.org/wiki/Public-key_cryptography

**GPKI** is being designed to automate and simplify the management of such a network. It is responsible for:
    * registering identities within the network
    * encrypting and decrypting messages from the network members

Design
------

**GPKI** leverages both git and gpg to provide its functionality. The system consists of two parts: private vault and
public repository. Vault is a GPG keychain storing every private and public key while the public repository is where
only the public keys end up for other members to see.

Identity
~~~~~~~~

Every identity is a tuple of (name, email, description), where names should allow easy identification of its owner. It
is possible for any user to own multiple identities, which might be beneficial when contacting external entities or if
one needs to manually partition the network. Although in most cases a single identity should be enough.

Where is the Certificate Authority?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The network is as secure as the git repository. New identities can only be added by the users with correct permissions,
hence there is no need for an explicit CA signing keys. For example, one could rely on merging the commits signed by a
trusted user.

Use Case
--------

Sometimes, people need to share with another person a message, which they would like to keep confidential. With the help
of **GPKI** it becomes as easy as installing it and maintaining a git repository (e.g. on github).

Examples might be: household/family networks or confidential team-members communication (e.g. sharing confidential
memos)
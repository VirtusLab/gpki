.. _sync:

sync
------
**Usage:**

.. code-block:: shell

    gpki sync

Adds new, approved identities to the local GPG keychain. Updates revoked identities and removes deleted ones.
For more context, see `identity` and `revoke` commands.

**Options:**

--keep-rejected-keys                          revoked public keys will not be removed from keyring
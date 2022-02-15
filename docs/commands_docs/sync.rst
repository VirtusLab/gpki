.. _sync:

sync
------
**Usage:**

.. code-block:: shell

    gpki sync

Synchronizes the local state with remote repository. Adds new keys if any available and removes revoked keys (unless disabled by a flag).

**Options:**

--keep-rejected-keys                          revoked public keys will not be removed from keyring
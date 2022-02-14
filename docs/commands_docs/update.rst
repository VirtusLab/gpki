.. _update:

update
------
**Usage:**

.. code-block:: shell

    gpki update

Synchronizes the local state with remote repository. Adds new keys if any available and removes revoked keys (unless disabled by a flag).

**Options:**

--keep-rejected-keys                          revoked public keys will not be removed from keyring
.. _revoke:

revoke
------
**Usage:**

.. code-block:: shell

    gpki revoke

Lists all available signatories and lets the user choose which one to revoke. Once signatory is selected, pull request with revocation file is issued.
After revocation of key, other users won't be able to decrypt messages signed with revoked key, which is useful when it is know the key was compromised.
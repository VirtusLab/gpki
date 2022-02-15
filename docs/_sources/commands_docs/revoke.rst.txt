.. _revoke:

revoke
------
**Usage:**

.. code-block:: shell

    gpki revoke

Revokes a locally created identity. Change will be reflected in the upstream repository once approved by the CA.

Messages created by this identity **after** the revocation will be treated as invalid as soon as the revocation request is approved and receiver synchronizes his local repository`.

Messages created **before** the revocation will still be treated as valid.
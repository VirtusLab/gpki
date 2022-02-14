.. _identity:

identity
--------
**Usage:**

.. code-block:: shell

    gpki identity <name> [--email] [--description]

Creates new identity <name>. Its associated key pair is added the into GPG keyring. Also, only public key is pushed  into upstream repository for Certificate Authority to review.
Since identity is immediately added to keyring, it allows preparing and sharing messages before waiting for approval.
If the name is already taken, identity can be replaced with a new key pair, optionally revoking the old one.

If optional ``--email`` or ``--description`` is provided, then those fields will be available in recipient's description.



**Options:**

--email                            Specifies email address associated with given identity
--description                      Short description of identity, e.g. its role


.. _identity:

identity
--------
**Usage:**

.. code-block:: shell

    gpki identity <name> [--email] [--description]

Creates new identity <name> for the user. Adds new private/public key pair into GPG keyring and pushes public key into git repository for Certificate Authority for a review under branch <name>/<fingerprint>.
If user already has identity called <name>, user is asked whether the previous public key needs to be revoked.

If optional ``--email`` or ``--description`` is provided, then those fields will be printed out when selecting recipients or signatory.



**Options:**

--email                            Specifies email address associated with given identity
--description                      Short description of identity, egz. purpose


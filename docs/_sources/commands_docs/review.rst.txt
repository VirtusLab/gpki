.. _review:

review
------
**Usage:**

.. code-block:: shell

    gpki review

Lists all pending changes to the repository and guides the user through accepting or rejecting any of them. Decision made will be pushed to the upstream repository. Only the trusted parties - Certificate Authorities - must be allowed to push the master branch.
Pending changes can be:

    a) generated identities
    b) imported identities

Identity revocations will be approved automatically.

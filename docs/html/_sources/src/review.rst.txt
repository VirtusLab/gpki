.. _review:

review
------
**Usage:**

.. code-block:: shell

    gpki review

``review`` command is reserved for the Certificate Authority or someone empowered to make changes in master/main branch.
At the beginning ``review`` command will merge all revoke requests into master.
Later the command looks for unmerged new identities or import requests and lists them to the user.
Certificate Authority can now decide which request to handle and make decision if requests should be merged to master/main branch or reject it.
If requests gets rejected, then its branch is automatically removed from repository.

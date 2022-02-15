.. _getting_started:

Getting started
===============
The prerequisite is having a dedicated git repository with appropriate security settings set up (i.e. only trusted users should be allowed to push changes to master branch).

When run for the first time, gpki will ask the user for the upstream repository URL.
Every message is encrypted and signed by one of the locally created identities.

To create one, use:

.. code-block:: shell

    gpki identity <name> [--email <email>] [--description <description>]

Other users will be able to communicate with this identity as soon as Certificate Authority approves it and they update their local repository. (see :ref:`identity`)

To synchronize with the upstream repository, use:

.. code-block:: shell

    gpki sync

Encrypt message from file or terminal with:

.. code-block:: shell

    gpki encrypt [--all/-a] [--input/-i <input_path>] [--output/-o <output_path>]

Decrypt message from file or terminal with:

.. code-block:: shell

    gpki decrypt [--input/-i <input_path>] [--output/-o <output_path>] [--sync/-s]
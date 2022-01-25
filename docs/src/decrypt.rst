.. _decrypt:

decrypt
-------
**Usage:**

.. code-block:: shell

    gpki decrypt [-o|--output <target_file>] [-i|--input <input_file>] [-u|--update]


Decrypts message or file content into console or specified output file.
If input file is not specified, user is asked to paste GPG message block into console.
If output file is not provided, decrypted message is printed out to the console.
It may happen that the message is signed with revoked key. In such a case, to make sure ``gpki`` operates on latest data from repository, it's adviced to pass ``-u/--update`` flag.

Note: both input and output path are relative by default, but there is possibility to pass absolute path.

**Options:**

-o, --output                        Specify target output file where decrypted message is written to.

-i, --input                         Specify source file, which content will be decrypted (must have GPG message block inside)

-u, --update                        updates GPG keyring with keys from the repository and removes revoked keys

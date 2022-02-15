.. _decrypt:

decrypt
-------
**Usage:**

.. code-block:: shell

    gpki decrypt [-o|--output <target_file>] [-i|--input <input_file>] [-s|--sync]


Decrypts the file or console-pasted message. Output is written either to the console or the specified file.
If input file is not specified, user is asked to paste GPG message block into console.
If output file is not provided, decrypted message is printed out to the console.
It may happen that the message is signed with revoked key. In such a case, to make sure ``gpki`` operates on latest data from repository, it's adviced to pass ``-s/--sync`` flag.

Note: Unless absolute, input and output paths are relative to the current working directory.

**Options:**

-o, --output                        Optionally, specifies where to store the decrypted message.

-i, --input                         Optionally, specifies from where to read the encrypted GPG message.

-s, --sync                          If present, local repository will be synchronized with the upstream before validating the keys.

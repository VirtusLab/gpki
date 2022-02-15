.. _encrypt:

encrypt
-------
**Usage:**

.. code-block:: shell

    gpki encrypt [-o|--output <target_file>] [-i|--input <source_file>] [-a|--all]

Encrypts a file or console-pasted message writing resulting GPG message block into the console or a file.
If input file is not specified, user is asked to write message in console.
If output file is not provided, encrypted message block is printed out to the console.
Message recipients are interactively selected by user or all of them are selected if ``-a/--all`` flag is set.

Note: Unless absolute, input and output paths are relative to the current working directory.

**Options:**

-o, --output                           Optionally, specifies where to store the encrypted message.

-i, --input                            Optionally, specifies from where to read the unencrypted message.

-a, --all                              Selects all available recipients.

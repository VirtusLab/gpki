.. _encrypt:

encrypt
-------
**Usage:**

.. code-block:: shell

    gpki encrypt [-o|--output <target_file>] [-i|--input <source_file>] [-a|--all]

Encrypts message or file content into GPG message block or into output file.
If input file is not specified, user is asked to write message in console.
If output file is not provided, encrypted message block is printed out to the console.
Message recipients are interactively selected by user or all of them are selected if ``-a/--all`` flag is set.

Note: both input and output path are relative by default, but there is possibility to pass absolute path.

**Options:**

-o, --output                           Specify target output file where encrypted message is written to.

-i, --input                            Specify source file, which content will be encrypted.

-a, --all                              Selects all available recipients.

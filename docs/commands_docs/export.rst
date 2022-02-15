.. _export:

export
------
**Usage:**

.. code-block:: shell

    gpki export <key_name_1 ... key_name_N> [-o|--output <target_file_path>]

Exports selected public keys into a file or the console as a GPG public key block.
The exported public key block is printed to console even if output file is specified.

Note: Unless absolute, output path is relative to the current working directory.

**Options:**

-o, --output                           Optionally, specifies where to store the exported keys

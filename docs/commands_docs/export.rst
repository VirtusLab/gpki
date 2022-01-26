.. _export:

export
------
**Usage:**

.. code-block:: shell

    gpki export <key_name_1 ... key_name_N> [-o|--output <target_file_path>]

Exports selected public keys into file or GPG public key block.
The exported public key block is printed to console even if output file is specified.

Note: output target files is created in current working directory by default. Provide relative or absolute path to target file if necessary (may require privilege to create path).

**Options:**

-o, --output                           Specifies the output target file where selected keys are exported to.

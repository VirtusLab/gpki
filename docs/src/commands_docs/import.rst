.. _import:

import
------
**Usage:**

.. code-block:: shell

    gpki import [-i|--input <file1 ... fileN>]

Imports recipients from console or file(s) if any is specified. Expected format is GPG public key block.
Every keys in the block or the file must be valid, otherwise the block/file is treated as corrupted and not imported.
Prints import summary divided into three sections: Succeeded, Unchanged and Failed imports.


Note: Unless absolute, input path is relative to the current working directory.

**Options:**

-i, --input                            Specifies the files from which keys should be imported


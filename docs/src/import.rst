.. _import:

import
------
**Usage:**

.. code-block:: shell

    gpki import [-i|--input <file1 ... fileN>]

Imports all public keys from GPG public key block or file(s), so later on those keys are available to use as recipients.
If input files are not specified, user is asked to paste the GPG public key block.
If at least one key from block/file is not imported successfully, then all keys from given block/file are treated as corrupted, and not added to GPG keyring.
Prints import summary report divided into three sections: Succeeded, Unchanged and Failed imports.


Note: provided files will be found only if they are placed in current working directory. If there is need to add files from different location, then relative path to the file must be specified.

**Options:**

-i, --input                            Specifies the file or files from which keys are going to be imported


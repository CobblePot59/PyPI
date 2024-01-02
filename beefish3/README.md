beefish3
=======

Fork of beefish : https://github.com/coleifer/beefish.git
<br>
Easy file encryption using pycryptodome.

![alt text](http://media.charlesleifer.com/blog/photos/beefish.jpg) 


installing
----------

    pip install pycryptodome beefish3

Dependencies:
* [pycryptodome](https://www.pycryptodome.org/)


command-line options
--------------------

Usage:

    beefish3.py [-tkedaq] in_file [out_file]

* ``-e`` - encrypt the provided ``in_file`` and write to ``out_file``
* ``-d`` - decrypt the provided ``in_file`` and write to ``out_file``
* ``-k`` - specify password as command-line argument (if unspecified you will
  be securely prompted).
* ``-a`` - use AES-256 instead of the default "Blowfish" cipher.
* ``-t`` - run test suite
* ``-q`` - quiet mode (controls verbosity of test output).


examples
--------

beefish3 can be used to encrypt and decrypt file-like objects:

    from beefish3 import encrypt, decrypt

    # encrypting
    with open('secrets.txt') as fh:
        with open('secrets.enc', 'wb') as out_fh:
            encrypt(fh, out_fh, 'secret p@ssword')

    # decrypting
    with open('secrets.enc') as fh:
        with open('secrets.dec', 'wb') as out_fh:
            decrypt(fh, out_fh, 'secret p@ssword')

you can use a shortcut if you like:

    from beefish3 import encrypt_file, decrypt_file

    # encrypting
    encrypt_file('secrets.txt', 'secrets.enc', 'p@ssword')

    # decrypting
    decrypt_file('secrets.enc', 'secrets.dec', 'p@ssword')


you can use it from the command-line:

    beefish3.py -e secrets.txt secrets.enc
    beefish3.py -d secrets.enc secrets.dec

to use AES-256 cipher instead of the default, which is blowfish:

    beefish3.py -a -e secrets.txt
    beefish3.py -a -d secrets.enc


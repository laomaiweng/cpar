cpar aims to be an encrypted and authenticated archiving tool, with strong guarantees that the archive contents can't be decrypted or tampered with without the archive password. Said archive password should also be resistant to brute force.

To achieve this, it merely leverages existing building blocks: the tar archive format and gzip/bzip2/lzma for compression, the ChaCha20 stream cipher for encryption, the Poly1305 MAC for authentication, and the Scrypt KDF for key derivation.

**It is currently a proof-of-concept, and should _NOT_ be considered production-ready. There are known weaknesses in the current implementation which need to be addressed.**

This first implementation in Python 3.6+ will likely be followed by an implementation in a compiled language, presumably Rust.

If you really want to try it out:
```
$ git clone https://github.com/laomaiweng/cpar
$ cd cpar
$ python3 -m venv venv
$ . ./venv/bin/activate
$ pip3 install -r requirements.txt
$ (cd ./venv/lib/python3/site-packages/cryptography; patch -p1) <cryptography-2.5-chacha20poly1305-stream-interface.patch
$ ./cpar.py --help
```

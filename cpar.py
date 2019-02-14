#!/usr/bin/env python3

import argparse
import contextlib
import getpass
import logging
import os
import shlex
import tarfile

import construct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidTag


#DEBUG
#logging.basicConfig(level=logging.DEBUG)


# file format:
#   header || tag || ciphertext
# header format:
#   magic || version || kdf params || cipher params
# kdf params format:
#   salt || n || r || p     # algo?
# cipher params format:
#   nonce                   # algo?
# ciphertext format:
#   compressed tarball      # compression algo detection is transparent (thx tarfile)

# TODOS:
# * check for scrypt support (seems to require >=openssl-1.1.0)
# * offer zipfile format?
# * symlink/hardlink dereference handling (-P/-H/-L shit)
# * comments / pydoc
# * document file format:
# ** why is the tag where it is
# ** what is included in the tag (as AAD/ciphertext)
# * list,extract: verify integrity first, store compressed archive in memory while doing so
# * list,extract: --optimistic to process the archive as its being decrypted (doc: security warning, for large archives)
# * extract: --traverse to extract files that would end up outside of the working directory (follow dir symlinks to abs/rel-with-.. paths, files with abs/rel-with-.. paths) (doc: security warning)
# * extract: --yolo = --optimistic --traverse (undocumented option)
# * list: --hash to display checksums of files in the archive (computed, not stored), default sha256
# * list: --check to check checksums of files in the archive against that of files on the filesystem
# * list: --json to dump contents in json format
# * --version switch
# * move --verbose under each action it applies to


VERSION = 0x1

# these are lists (rather than dicts) since order matters: the first item is the default one
#TODO: description?
CIPHERS = [
    ('chacha20-poly1305', (algorithms.ChaCha20, modes.Poly1305)),
    ('aes-gcm',           (algorithms.AES,      modes.GCM))
]
ZIPPERS = [
    ('lzma',  'xz'),
    ('bzip2', 'bz2'),
    ('gzip',  'gz'),
    ('none',  'tar')
]

BACKEND = default_backend()

HEADER = construct.Struct(
    'magic'         / construct.Const(b'CPAR'),
    'version'       / construct.Int16ul,
    'kdf_params'    / construct.Struct(     #TODO: algo?
        'salt'      / construct.Bytes(16),
        'n'         / construct.Int32ul,
        'r'         / construct.Int8ul,
        'p'         / construct.Int8ul
    ),
    'cipher_params' / construct.Struct(     #TODO: algo?
        'nonce'     / construct.Bytes(16)   #TODO: size?
    )
)
        

class FileEncryptor:
    def __init__(self, filename, encryptor):
        self._fd = open(filename, 'wb')
        self._encryptor = encryptor
        self._aad = b''
        self._tag_pos = None
    
    def init(self, encryptor):
        if self._encryptor is not None:
            raise RuntimeError(f'encryption already initialized for {self.name}')
        self._encryptor = encryptor
        if len(self._aad) > 0:
            encryptor.authenticate_additional_data(self._aad)
            self._aad = b''

    def write_aad(self, data):
        if self._encryptor is not None:
            self._encryptor.authenticate_additional_data(data)
        else:
            self._aad += data
        return self._fd.write(data)

    def write_tag(self):
        # remember where to write the tag
        self._tag_pos = self._fd.tell()
        # write a placeholder
        self._fd.write(b'\x00' * self._encryptor._ctx._mode._min_tag_length)
        logging.debug(f'[FileDecryptor::write_tag()] pos={self._tag_pos}')

    def write(self, data):
        return self._fd.write(self._encryptor.update(data))

    def close(self):
        try:
            # finalize
            data = self._fd.write(self._encryptor.finalize())
            # write the tag
            if self._tag_pos is not None:
                self._fd.seek(self._tag_pos, os.SEEK_SET)
            self._fd.write(self._encryptor.tag)
            logging.debug(f'[FileEncryptor::close()] tag_pos={self._tag_pos} tag={self._encryptor.tag.hex()}')
            return data
        finally:
            self._fd.close()

    @property
    def name(self):
        return self._fd.name


class FileDecryptor:
    def __init__(self, filename, decryptor):
        self._fd = open(filename, 'rb')
        total_size = self._fd.seek(0, os.SEEK_END)  #DEBUG
        self._fd.seek(0, os.SEEK_SET)               #DEBUG
        logging.debug(f'[FileDecryptor::__init__()] filename={filename} total_size={total_size}')
        self._decryptor = None
        self._aad = b''
        self._tag = b''

        if decryptor is not None:
            self.init(decryptor)

    def init(self, decryptor):
        if self._decryptor is not None:
            raise RuntimeError(f'decryption already initialized for {self.name}')
        self._decryptor = decryptor

        # process any AAD read up to this point
        if len(self._aad) > 0:
            decryptor.authenticate_additional_data(self._aad)
            self._aad = b''

    def read_aad(self, size):
        logging.debug(f'[FileDecryptor::read_aad()] size={size}')
        data = self._fd.read(size)
        if self._decryptor is None:
            self._aad += data
        else:
            self._decryptor.authenticate_additional_data(data)
        return data

    def read_tag(self):
        pos = self._fd.tell()   #DEBUG
        self._tag = self._fd.read(self._decryptor._ctx._mode._min_tag_length)
        logging.debug(f'[FileDecryptor::read_tag()] pos={pos} tag={self._tag.hex()}')

    def read(self, size):
        logging.debug(f'[FileDecryptor::read()] size={size}')
        return self._decryptor.update(self._fd.read(size))

    def close(self):
        logging.debug(f'[FileDecryptor::close()]')
        try:
            return self._decryptor.finalize_with_tag(self._tag)
        finally:
            self._fd.close()

    @property
    def name(self):
        return self._fd.name


def guess_by_name(name, options, label):
    guesses = [o for (n, o) in options if n.startswith(name)]
    if len(guesses) == 0:
        raise RuntimeError(f'{label} name "{name}" does not match any {label}')
    if len(guesses) > 1:
        raise RuntimeError(f'{label} name "{name}" matches several {label}s')
    return guesses[0]

def get_password():
    #TODO: confirm!
    password = getpass.getpass()
    logging.debug(f'[get_password()] password={shlex.quote(password)}')
    return password

def create(args):   #TODO: verbosity
    # process args
    cipher = guess_by_name(args.cipher, CIPHERS, 'cipher')
    zipper = guess_by_name(args.zipper, ZIPPERS, 'zipper')

    # setup encryption
    salt = os.urandom(16)
    n, r, p = 2**18, 8, 1   # 2**18 is a middle ground between 2**14 (<100ms, interactive login) and 2**20 (<5s, sensitive file)
    kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p, backend=BACKEND)
    key = kdf.derive(get_password().encode('utf-8'))
    logging.debug(f'[create()] key={key.hex()}')
    nonce = os.urandom(16)  #TODO: get size from somewhere
    cipher = Cipher(algorithms.ChaCha20(key, nonce), modes.Poly1305(), backend=BACKEND) #TODO: use args.cipher

    # prepare the header
    header = {
        'version': VERSION,
        'kdf_params': {
            'salt': salt,
            'n': n,
            'r': r,
            'p': p
        },
        'cipher_params': {
            'nonce': nonce
        }
    }

    # write the file
    with contextlib.closing(FileEncryptor(args.archive, cipher.encryptor())) as fd:
        # build the header
        fd.write_aad(HEADER.build(header))

        # write the tag (placeholder)
        fd.write_tag()

        # create the archive
        with contextlib.closing(tarfile.open(fileobj=fd, mode='w|' + zipper)) as tar:
            for f in args.files:
                tar.add(f)

def read(args, action):
    # read the file
    with contextlib.closing(FileDecryptor(args.archive, None)) as fd:    # no decryptor yet
        # parse the header
        header = HEADER.parse(fd.read_aad(HEADER.sizeof()))

        # setup encryption
        kdf_params = header['kdf_params']
        kdf = Scrypt(salt=kdf_params['salt'], length=32, n=kdf_params['n'], r=kdf_params['r'], p=kdf_params['p'], backend=BACKEND)
        key = kdf.derive(get_password().encode('utf-8'))
        logging.debug(f'[read()] key={key.hex()}')
        cipher_params = header['cipher_params']
        cipher = Cipher(algorithms.ChaCha20(key, cipher_params['nonce']), modes.Poly1305(), backend=BACKEND)
        fd.init(cipher.decryptor())

        # read the tag
        fd.read_tag()

        # read the archive
        tar = tarfile.open(fileobj=fd, mode='r|*')
        action(tar)

def extract(args):  #TODO: verbosity
    read(args, lambda tar: tar.extractall(args.directory))  #TODO: fail without extracting if bad integrity

def list(args):
    read(args, lambda tar: tar.list(args.verbose > 0))  #TODO: fail without listing if bad integrity

def list_ciphers(args):
    for (name, _) in CIPHERS:
        print(name)

def list_zippers(args):
    for (name, _) in ZIPPERS:
        print(name)

def main():
    parser = argparse.ArgumentParser(description='Encrypted and authenticated file archiving tool.')
    parser.set_defaults(func=lambda args: parser.print_usage())
    subs = parser.add_subparsers()

    parser_create = subs.add_parser('create', aliases=['c'], help='create an archive')
    parser_create.add_argument('-C', '--cipher', default=CIPHERS[0][0], help='cipher to use for encryption')
    parser_create.add_argument('-Z', '--zipper', default=ZIPPERS[0][0], help='algorithm to use for compression')
    #TODO: --single: compress+encrypt single file, w/o tar/zip container
    #TODO: compression level
    parser_create.add_argument('archive', help='archive filename')
    parser_create.add_argument('files', nargs='*', help='files to archive')
    parser_create.set_defaults(func=create)

    parser_extract = subs.add_parser('extract', aliases=['x'], help='extract files from an archive')
    parser_extract.add_argument('-d', '--directory', default='.', help='extraction directory')
    parser_extract.add_argument('archive', help='archive filename')
    parser_extract.set_defaults(func=extract)

    parser_list = subs.add_parser('list', aliases=['l'], help='list archive contents')
    parser_list.add_argument('archive', help='archive filename')
    parser_list.set_defaults(func=list)

    subs.add_parser('ciphers', help='list available ciphers').set_defaults(func=list_ciphers)
    subs.add_parser('zippers', help='list available compression algorithms').set_defaults(func=list_zippers)

    parser.add_argument('-v', '--verbose', default=0, action='count', help='be verbose')

    args = parser.parse_args()
    return args.func(args)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3

# basics
import os
import readline
import sys
import argparse
import getpass
from base64 import b64encode, b64decode

# protobuf serialization
from aenker_pb2 import AuthenticatedCiphertextBlob as Aenker

# authenticated encryption primitives
# https://cryptography.io/en/latest/hazmat/primitives/aead/
from cryptography.hazmat.primitives.ciphers import aead as AEAD

# key derivation functions
# https://argon2-cffi.readthedocs.io/en/stable/api.html
from argon2.low_level import hash_secret_raw as argon2_raw, Type as argon2_type

# prompt for input on stderr
def einput(text): sys.stderr.write(text); return input()

# getpass and encode
passwd = lambda prompt='Enter Password: ': getpass.getpass(prompt).encode('utf-8')

# split string at index
split = lambda string, index: (string[:index], string[index:])

# get aead cipher depending on arguments
aead = lambda key, cipher: AEAD.AESGCM(key) if cipher == Aenker.cipher_type.Value('AESGCM') else AEAD.ChaCha20Poly1305(key)

# key derivation wrappers
class KDF:

  argon2 = lambda password, salt, i=30, m=15, p=4 :\
    split(argon2_raw(password, salt, time_cost=i, memory_cost=2**m, parallelism=p, hash_len=44, type=argon2_type.I), 12)

# parse commandline arguments
argparser = argparse.ArgumentParser()

# arg: input file
argparser.add_argument('file', nargs='?', help='input file (default: sys.stdin)')

# arg: subcommand
arg_mode = argparser.add_mutually_exclusive_group()
arg_mode.add_argument('-e', '--encrypt', action='store_true', help='encrypt file (default)')
arg_mode.add_argument('-d', '--decrypt', action='store_true', help='decrypt file')

# arg: output file
argparser.add_argument('-o', '--out', metavar='file', help='output file (default: sys.stdout)')

# arg: key derivation mode
arg_kdf = argparser.add_mutually_exclusive_group()
arg_kdf.add_argument('-r', '--random', action='store_true', help='use a randomly generated key')
arg_kdf.add_argument('-p', '--password', action='store_true', help='use Argon2 to derive key (default)')

# arg: cipher algorithm
arg_cipher = argparser.add_mutually_exclusive_group()
arg_cipher.add_argument('-c', '--chacha20', action='store_true', help='use ChaCha20Poly1305 cipher (default)')
arg_cipher.add_argument('-g', '--aes-gcm', action='store_true', help='use AES-GCM cipher')

args = argparser.parse_args()

# open files
with \
  open(args.file, mode='rb') if args.file else sys.stdin.buffer as infile  ,\
  open(args.out,  mode='wb') if args.out else sys.stdout.buffer as outfile :

  ae = Aenker()

  # decryption
  if args.decrypt:

    ae.ParseFromString(infile.read())

    # random key, stored nonce
    if ae.kdf == ae.kdf_type.Value('None'):
      nonce = ae.nonce
      key = b64decode(einput('Enter Base64 encoded key: '))

    # password-derived key and nonce, stored salt
    else:
      nonce, key = KDF.argon2(passwd(), ae.nonce)

    # get cipher type and decrypt
    message = aead(key, ae.cipher).decrypt(nonce, ae.text, None)
    outfile.write(message)

  # encryption
  else:

    # generate random key, store nonce
    if args.random:
      nonce = ae.nonce = os.urandom(12)
      key = os.urandom(32)
      print('Encryption key:', b64encode(key).decode(), file=sys.stderr)

    # password-derived key and nonce, store salt
    else:
      ae.kdf = ae.kdf_type.Value('Argon2')
      ae.nonce = os.urandom(12)
      nonce, key = KDF.argon2(passwd(), ae.nonce)

    # set cipher type and encrypt
    if args.aes_gcm: ae.cipher = ae.cipher_type.Value('AESGCM')
    ae.text = aead(key, ae.cipher).encrypt(nonce, infile.read(), None)
    outfile.write(ae.SerializeToString())


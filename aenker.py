#!/usr/bin/env python3

# basics
import os
import readline
import sys
import argparse
from getpass import getpass
from base64 import b64encode, b64decode

# protobuf serialization
from aenker_pb2 import AuthenticatedCiphertextBlob as Aenker

# authenticated encryption primitives
# https://cryptography.io/en/latest/hazmat/primitives/aead/
from cryptography.hazmat.primitives.ciphers import aead as AEAD

# key derivation functions
# https://argon2-cffi.readthedocs.io/en/stable/api.html
from argon2.low_level import hash_secret_raw as Argon2Hash, Type as Argon2Type

# prompt on stderr, like getpass
def einput(text): sys.stderr.write(text); return input()

# key derivation wrappers
class KDF:

  def argon2(password, salt=None, time_cost=30, memory_cost=15):
    return Argon2Hash(password, salt if salt != None else os.urandom(16),
        time_cost, 2**memory_cost, parallelism=4, hash_len=12+32, type=Argon2Type.I)

# parse commandline arguments
argparser = argparse.ArgumentParser()

# arg: input file
argparser.add_argument('file', nargs='?', help='input file (default: sys.stdin)')

# arg: mode
arg_mode = argparser.add_mutually_exclusive_group()
arg_mode.add_argument('-e', '--encrypt', action='store_true', help='encrypt file')
arg_mode.add_argument('-d', '--decrypt', action='store_true', help='decrypt file')

# arg: output file
argparser.add_argument('-o', '--out', metavar='file', help='output file (default: sys.stdout)')

args = argparser.parse_args()

# dummy: get password-derived key
if False: print(KDF.argon2(getpass('Enter password: ').encode('utf-8')))

# open files
with \
  open(args.file, mode='rb') if args.file else sys.stdin.buffer as infile  ,\
  open(args.out,  mode='wb') if args.out else sys.stdout.buffer as outfile :


  if args.decrypt:

    ae = Aenker()
    ae.ParseFromString(infile.read())

    key = b64decode(einput('Enter Base64 encoded key: '))
    aead = AEAD.ChaCha20Poly1305(key)
    message = aead.decrypt(ae.nonce, ae.text, None)

    outfile.write(message)

  else:

    ae = Aenker()

    key = os.urandom(32)
    ae.nonce = os.urandom(12)

    print('Encryption key:', b64encode(key).decode(), file=sys.stderr)
    aead = AEAD.ChaCha20Poly1305(key)
    ae.text = aead.encrypt(ae.nonce, infile.read(), None)

    outfile.write(ae.SerializeToString())



# spec:
# for randomly keyed:     0x00 || null[3] || nonce[16] || ciphertext[+]         secret: key[32]
# for password derived:   0x01 || KDF options[3] || salt[16] || ciphertext [+]
#       |--> argon2 hash output: 16 + 32 = nonce + key for AEAD
#       \--> use KDF options as AEAD associated data, just for shits and giggles

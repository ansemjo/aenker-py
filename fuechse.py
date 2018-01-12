#!/usr/bin/env python3

# basics
import os
import readline
import sys
from argparse import ArgumentParser, FileType
from getpass import getpass
from base64 import b64encode, b64decode

# protobuf serialization
from ciphertext_pb2 import CiphertextBlob

# authenticated encryption primitives
# https://cryptography.io/en/latest/hazmat/primitives/aead/
from cryptography.hazmat.primitives.ciphers import aead as AEAD

# key derivation functions
# https://argon2-cffi.readthedocs.io/en/stable/api.html
from argon2.low_level import hash_secret_raw as Argon2Hash, Type as Argon2Type

# prompt on stderr, like getpass
def prompt(text=None):
  if text: sys.stderr.write(text)
  return input('')

class KDF:

  def argon2(password: bytes, salt: bytes = None, time_cost: int = 30, memory_cost: int = 15):
    return Argon2Hash(password, salt if salt != None else os.urandom(16), time_cost, 2**memory_cost, parallelism=4, hash_len=12+32, type=Argon2Type.I)


argparser = ArgumentParser()

# input file and mode
arg_mode = argparser.add_mutually_exclusive_group(required=True)
arg_mode.add_argument('-e', '--encrypt', type=FileType('rb'), metavar='file', help='encrypt file')
arg_mode.add_argument('-d', '--decrypt', type=FileType('rb'), metavar='file', help='decrypt file')

# output file
argparser.add_argument('-o', '--out',  type=FileType('wb'), default='/dev/stdout', metavar='file', help='output file (default: <stdout>)')

args = argparser.parse_args()


# old: generate
if False:

  pw = getpass('Enter password: ')
  print(KDF.argon2(pw.encode('utf-8')))

args.file = args.encrypt if args.encrypt else args.decrypt
with args.file as infile, args.out as outfile:

  if args.encrypt:

    blob = CiphertextBlob()

    key = os.urandom(32)
    blob.nonce = os.urandom(12)

    print('Encryption key:', b64encode(key).decode(), file=sys.stderr)
    aead = AEAD.ChaCha20Poly1305(key)
    blob.text = aead.encrypt(blob.nonce, infile.read(), None)

    outfile.write(blob.SerializeToString())


  elif args.decrypt:

    blob = CiphertextBlob()
    blob.ParseFromString(infile.read())

    key = b64decode(prompt('Enter Base64 encoded key: '))
    aead = AEAD.ChaCha20Poly1305(key)
    message = aead.decrypt(blob.nonce, blob.text, None)

    outfile.write(message)


# spec:
# for randomly keyed:     0x00 || null[3] || nonce[16] || ciphertext[+]         secret: key[32]
# for password derived:   0x01 || KDF options[3] || salt[16] || ciphertext [+]
#       |--> argon2 hash output: 16 + 32 = nonce + key for AEAD
#       \--> use KDF options as AEAD associated data, just for shits and giggles

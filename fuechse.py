#!/usr/bin/env python3

# basics
from os import urandom
#import readline
from sys import stderr, stdout
from argparse import ArgumentParser, FileType
from getpass import getpass
from base64 import b64encode, b64decode

# protobuf serialization
from ciphertext_pb2 import CiphertextBlob

# authenticated encryption primitives
from cryptography.hazmat.primitives.ciphers import aead as AEAD

# key derivation functions
from argon2.low_level import hash_secret_raw as Argon2Hash, Type as Argon2Type

# prompt on stderr, like getpass
def prompt(text=None):
  if text: stderr.write(text)
  return input()

class KDF:

  def argon2(password: bytes, salt: bytes = None, time_cost: int = 30, memory_cost: int = 15):
    return Argon2Hash(password, salt if salt != None else urandom(16), time_cost, 2**memory_cost, parallelism=4, hash_len=12+32, type=Argon2Type.I)


argparser = ArgumentParser()

arg_mode = argparser.add_mutually_exclusive_group(required=True)
arg_mode.add_argument('-e', '--encrypt', action='store_true', help='encrypt file')
arg_mode.add_argument('-d', '--decrypt', action='store_true', help='decrypt file')

argparser.add_argument('-f', '--file', type=FileType('rb'), default='/dev/stdin',  metavar='file', help='input file (default: <stdin>)')
argparser.add_argument('-o', '--out',  type=FileType('wb'), default='/dev/stdout', metavar='file', help='output file (default: <stdout>)')

args = argparser.parse_args()


# old: generate
if False:

  pw = getpass('Enter password: ')
  print(KDF.argon2(pw.encode('utf-8')))


with args.file as infile, args.out as outfile:

  if args.encrypt:

    blob = CiphertextBlob()

    key = urandom(32)
    blob.nonce = urandom(12)

    print('Key   :', b64encode(key).decode(), file=stderr)
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

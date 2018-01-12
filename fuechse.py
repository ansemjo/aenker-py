#!/usr/bin/env python3

# basics
from os import urandom
from argparse import ArgumentParser, FileType
from getpass import getpass

# authenticated encryption libraries
from cryptography.hazmat.primitives.ciphers import aead as AEAD

# key derivation functions
from argon2.low_level import hash_secret_raw as Argon2Hash, Type as Argon2Type


class KDF:

  def argon2(password: bytes, salt: bytes = None, time_cost: int = 30, memory_cost: int = 15):
    return Argon2Hash(password, salt if salt != None else urandom(16), time_cost, 2**memory_cost, parallelism=4, hash_len=16+32, type=Argon2Type.I)


argparser = ArgumentParser()
subparser = argparser.add_subparsers(title='command', dest='command')

cmd_generate = subparser.add_parser('generate')

cmd_encrypt = subparser.add_parser('encrypt')
cmd_encrypt.add_argument('--key', required=True)
cmd_encrypt.add_argument('-r', '--read', type=FileType('rb'), default='/dev/stdin')
cmd_encrypt.add_argument('-w', '--write', type=FileType('wb'), default='/dev/stdout')

cmd_decrypt = subparser.add_parser('decrypt')


args = argparser.parse_args()

if args.command == None: argparser.print_help()

if args.command == 'generate':

  pw = getpass('Enter password: ')
  print(KDF.argon2(pw.encode('utf-8')))

if args.command == 'encrypt':

  with args.read as fin, args.write as fout:
    f = Fernet(args.key)
    fout.write(f.encrypt(fin.read()))


# spec:
# for randomly keyed:     0x00 || null[3] || nonce[16] || ciphertext[+]         secret: key[32]
# for password derived:   0x01 || KDF options[3] || salt[16] || ciphertext [+]
#       |--> argon2 hash output: 16 + 32 = nonce + key for AEAD
#       \--> use KDF options as AEAD associated data, just for shits and giggles

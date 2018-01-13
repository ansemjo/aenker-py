#!/usr/bin/env python3

# basics
import os
import readline
import sys
import argparse
import getpass
from base64 import b64encode, b64decode

# protobuf serialization
try: Aenker = AuthenticatedCiphertextBlob
except NameError:
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
aead = lambda key, cipher: AEAD.AESGCM(key) if cipher == Aenker.cipher_t.Value('AESGCM') else AEAD.ChaCha20Poly1305(key)

# key derivation wrappers
class KDF:

  argon2 = lambda password, blob :\
    split(argon2_raw(password, blob.nonce, \
    blob.kdf_opts.time_cost, 2**blob.kdf_opts.memory_cost, blob.kdf_opts.parallelism, \
    hash_len=44, type=argon2_type.I), 12)

# parse commandline arguments
argparser = argparse.ArgumentParser()

# arg_grp: input / output files
grp_io = argparser.add_argument_group('file selection')
grp_io.add_argument('file', nargs='?', help='input file (default: sys.stdin)')
grp_io.add_argument('-o', '--out', metavar='file', help='output file (default: sys.stdout)')

# arg: subcommand
arg_cmd = argparser.add_mutually_exclusive_group()
arg_cmd.add_argument('-e', '--encrypt', action='store_true', help='encrypt file (default)')
arg_cmd.add_argument('-d', '--decrypt', action='store_true', help='decrypt file')

# arg_grp: encryption options
grp_options = argparser.add_argument_group('Encryption options', description="""
The following options are only useful during encryption.
Choices are saved in the serialized file.
""")

# arg_grp: key derivation mode
grp_kdf = argparser.add_argument_group('Key generation')
arg_kdf = grp_kdf.add_mutually_exclusive_group()
arg_kdf.add_argument('-r', '--random', action='store_true', help='use a random key from os.urandom()')
arg_kdf.add_argument('-p', '--password', action='store_true', help='use Argon2 to derive key (default)')
grp_kdf.add_argument('--kdf-time-cost', type=int, help='KDF time cost / iterations (default: 21)', metavar='i')
grp_kdf.add_argument('--kdf-memory-cost', type=int, help='KDF memory cost, power of two (default: 15)', metavar='m')
grp_kdf.add_argument('--kdf-parallelism', type=int, help='KDF parallelism (default: 4)', metavar='p')


# arg_grp: cipher algorithm
grp_cipher = argparser.add_argument_group('Cipher selection')
arg_cipher = grp_cipher.add_mutually_exclusive_group()
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
    if ae.kdf == ae.kdf_t.Value('None'):
      nonce = ae.nonce
      key = b64decode(einput('Enter Base64 encoded key: '))

    # password-derived key and nonce, stored salt
    else:
      nonce, key = KDF.argon2(passwd(), ae)

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
      ae.kdf = ae.kdf_t.Value('Argon2')
      if args.kdf_time_cost:    ae.kdf_opts.time_cost   = args.kdf_time_cost
      if args.kdf_memory_cost:  ae.kdf_opts.memory_cost = args.kdf_memory_cost
      if args.kdf_parallelism:  ae.kdf_opts.parallelism = args.kdf_parallelism
      ae.nonce = os.urandom(12)
      nonce, key = KDF.argon2(passwd(), ae)

    # set cipher type and encrypt
    if args.aes_gcm: ae.cipher = ae.cipher_t.Value('AESGCM')
    ae.text = aead(key, ae.cipher).encrypt(nonce, infile.read(), None)
    outfile.write(ae.SerializeToString())


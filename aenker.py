#!/usr/bin/env python3

# basics
import os
import readline
import sys
import argparse
import getpass
import ctypes, ctypes.util
import resource
from base64 import b64encode, b64decode

# authenticated encryption primitives
# https://cryptography.io/en/latest/hazmat/primitives/aead/
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305 as chacha

# int encoding
pack = lambda i, l=4: i.to_bytes(l, byteorder='big')
unpack = lambda b: int.from_bytes(b, byteorder='big')

# parse commandline arguments
argparser = argparse.ArgumentParser()

# arg_grp: input / output files
grp_io = argparser.add_argument_group('file selection')
grp_io.add_argument('infile', nargs='?', help='input file (default: sys.stdin)')
grp_io.add_argument('-o', '--out', metavar='file', help='output file (default: sys.stdout)')

# arg: subcommand
arg_cmd = argparser.add_mutually_exclusive_group()
arg_cmd.add_argument('-e', '--encrypt', action='store_true', help='encrypt file (default)')
arg_cmd.add_argument('-d', '--decrypt', action='store_true', help='decrypt file')
arg_cmd.add_argument('-g', '--genkey', action='store_true', help='generate keyfile')

# arg_grp: key material mode
grp_kdf = argparser.add_argument_group('key material')
arg_kdf = grp_kdf.add_mutually_exclusive_group()
arg_kdf.add_argument('-r', '--random', action='store_true', help='random key from os.urandom() (default)')
arg_kdf.add_argument('-k', '--key', help='32-byte base64-encoded keyfile or argument')

args = argparser.parse_args()

# read key from file
def readkey(file):
  with open(file, mode='rb') as k:
    return k.read()

# parse base64 string as 32 byte key
def parsekey(st, length=32):
  key = b64decode(st)
  memzero(st)
  if len(key) != length:
    raise ValueError(f'key has invalid length ({len(key)} != {length})')
  return key

# try to read key from file or argument
def getkey(arg):
  try: return readkey(arg)
  except: return arg

# some best-effort security measures
# https://github.com/myfreeweb/pysectools
try:
  libc = ctypes.CDLL(ctypes.util.find_library("c"))
  libc.mlockall(2)
  resource.setrlimit(resource.RLIMIT_CORE, [0, 0])
except:
  pass

# attempt to clear a string from memory
def memzero(s):
  try:
    bufsize = len(s) + 1
    offset = sys.getsizeof(s) - bufsize
    location = id(s) + offset
    ctypes.memset(location, 0, bufsize)
    return True
  except:
    return False

# open files
with \
  open(args.infile, mode='rb') if args.infile else sys.stdin.buffer as infile  ,\
  open(args.out, mode='wb') if args.out else sys.stdout.buffer as outfile :

  # magic bytes and associated data
  MAGIC = b'aenker'
  MEK_AD = b'aenker media encryption key'
  CTX_AD = b'aenker ciphertext'

  # conservative chunksize of 64kB
  CHUNK = 64*1024

  # keygen
  if args.genkey:

    outfile.write(b64encode(os.urandom(32)) + b'\n')

  # decryption
  elif args.decrypt:

    if MAGIC != infile.read(len(MAGIC)):
      raise ValueError('invalid magic bytes')

    if args.key is not None:
      kek = getkey(args.key)
    else:
      sys.stdin = open('/dev/tty')
      kek = input('Enter Base64 encoded key: ')

    kek = parsekey(kek)

    nonce = infile.read(12)
    mek = infile.read(48)

    mek = chacha(kek).decrypt(nonce, mek, MEK_AD)
    memzero(kek)

    # TODO: currently no detection of missing chunks at the end
    ctr = 0
    aead = chacha(mek)
    while True:
      ctr += 1
      length = infile.read(4)
      if ctr > 1 and len(length) == 0:
        break
      if len(length) != 4:
        raise ValueError('expected a 32 bit chunksize')
      length = unpack(length)
      #print(f'unpacked chunksize: {length}', file=sys.stderr)
      ciphertext = infile.read(length)
      if length == 0 or length != len(ciphertext):
        raise ValueError('unexpected EOF')
      #print(f'read chunksize: {len(ciphertext)}', file=sys.stderr)
      message = aead.decrypt(pack(ctr, 12), ciphertext, CTX_AD)
      outfile.write(message)
    memzero(mek)

  # encryption
  else:

    # media encryption
    mek = os.urandom(32)
    nonce = os.urandom(12) # TODO: nonce is too small for random choice with same key

    # generate random key encryption key
    if args.key is not None:
      kek = parsekey(getkey(args.key))
    else:
      kek = os.urandom(32)
      print('Encryption key:', b64encode(kek).decode(), file=sys.stderr)

    outfile.write(MAGIC)
    outfile.write(nonce)
    
    mekct = chacha(kek).encrypt(nonce, mek, MEK_AD)
    memzero(kek)
    outfile.write(mekct)

    ctr = 0
    aead = chacha(mek)
    while True:
      ctr += 1
      chunk = infile.read(CHUNK)
      if len(chunk) == 0:
        break
      ciphertext = aead.encrypt(pack(ctr, 12), chunk, CTX_AD)
      outfile.write(pack(len(ciphertext)))
      outfile.write(ciphertext)
    memzero(mek)


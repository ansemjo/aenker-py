**DEPRECATED** - use [ansemjo/aenker](https://github.com/ansemjo/aenker) instead

# aenker

`authenticated encryption ~> aencr ~> aenker`

Shows some resemblance to the German word 'Anker'.

## What is this?

This is a simple Python 3 script to wrap around [`python-cryptography`](https://pypi.python.org/pypi/cryptography)
and [Argon2](https://pypi.python.org/pypi/argon2_cffi).

I was looking for a simple commandline utility to use some form of
authenticated encryption - in particular ChaCha20Poly1305 or AES-GCM -
on the commandline for simple files. I didn't find any, so I set out to
write my own. _(Of course, there is still the symmetric mode of GPG)_

__Note:__ I didn't actually write any of the crypto. I am just plugging
together some low-level functions from readily-made cryptographic
libraries. Let's hope I didn't make any cruel mistakes while doing that.

On-disk format uses Google's [`protobuf2`](https://developers.google.com/protocol-buffers/docs/proto),
so interfaces in other languages should be easily achievable.

## Installation

Clone `git clone ..` and install `make install` or simply use `./aenker.py` after compiling
the protocol buffers with `protoc --python_out=. aenker.proto`.

Requires packages from PyPI:
- `cryptography`
- `argon2_cffi`

Requires `protoc` to compile the protocol buffers.

## Usage

For most up-to-date usage information run `./aenker.py --help`.

![aenker-usage](https://user-images.githubusercontent.com/11139925/34902789-8523a164-f81a-11e7-96f4-348e17228b71.png)


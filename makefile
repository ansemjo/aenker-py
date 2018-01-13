.PHONY : help install clean

PREFIX = /usr/local
BIN = aenker
MODE = -m 755 -o root -g root

help :
	@echo 'run `make install` to install $(BIN) in $(PREFIX)/bin'

aenker_pb2.py :
	protoc --python_out=. aenker.proto

install : aenker_pb2.py aenker.py
	echo '#!/usr/bin/env python3' | cat - aenker_pb2.py aenker.py | install /dev/stdin $(MODE) -T $(PREFIX)/bin/$(BIN)

clean :
	[ -d .git ] && git clean -fdx || rm -rf *_pb2.py __pycache__

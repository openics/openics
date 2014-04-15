#!/bin/bash

make clean 2>/dev/null

rm -rf m4 autom4te.cache/ aclocal.m4 build-* config.* configure depcomp install-sh libtool ltmain.sh Makefile Makefile.in stamp-h1 nids/libnids.* nids/nids.h 2>/dev/null
find . -name '.libs' -exec rm -rf {} 2>/dev/null \;
find . -name '.deps' -exec rm -rf {} 2>/dev/null \;
find . -name 'Makefile' -exec rm -f {} 2>/dev/null \;
find . -name 'Makefile.in' -exec rm -f {} 2>/dev/null \;
find . -name '*.so' -exec rm -f {} 2>/dev/null \;
find . -name '*.la' -exec rm -f {} 2>/dev/null \;
find . -name '*.o' -exec rm -f {} 2>/dev/null \;


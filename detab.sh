#!/bin/bash

gcc -o detab detab.c
./detab 4 *.c doc/dd-* etc/ics/scenario.d/*.ics src/libics/*.[hc] src/icsids/*.[hc]
rm -f detab

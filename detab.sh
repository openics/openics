#!/bin/bash

gcc -o detab detab.c
./detab 4 *.c README doc/* src/libics/*.[hc] src/icsids/*.[hc]
rm -f detab

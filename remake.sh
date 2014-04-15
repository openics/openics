#!/bin/bash
echo
echo stderr will be in build-stderr
echo stdout will be in build-stdout
echo

echo -e "STDERR:\n\n"  >build-stderr
echo -e "STDOUT:\n\n"  >build-stdout

echo "### ./cleanup.sh" |tee -a build-stderr |tee -a build-stdout
./cleanup.sh 2>>build-stderr >>build-stdout

echo "### ./nids/mknids" |tee -a build-stderr |tee -a build-stdout
pushd `pwd` 2>&1 >/dev/null
cd nids
./mknids 2>>../build-stderr >>../build-stdout
popd 2>&1 >/dev/null

export CFLAGS=-g3

echo "### aclocal"      |tee -a build-stderr |tee -a build-stdout
aclocal 2>>build-stderr >>build-stdout

echo "### automake"     |tee -a build-stderr |tee -a build-stdout
automake --add-missing 2>>build-stderr >>build-stdout

echo "### ./autogen.sh" |tee -a build-stderr |tee -a build-stdout
./autogen.sh 2>>build-stderr >>build-stdout

echo "### ./configure" |tee -a build-stderr |tee -a build-stdout
./configure 2>>build-stderr >>build-stdout

echo "### make" |tee -a build-stderr |tee -a build-stdout
make 2>>build-stderr >>build-stdout

if [[ -x src/icsids/icsids ]]; then
	echo -e "\nSuccess\n"
else
	echo -e "\nBuild failed\n"
fi


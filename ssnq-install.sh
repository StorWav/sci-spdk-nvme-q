#!/bin/sh

if [ -d "build" ]; then
	echo "ERROR: Directory 'build' exists. Exiting..."
	exit 1
fi

path_file="SSNQ.path"
sci_dir=$(awk -v token="SCI_DIR" -F ':=' '$1 ~ token {print $2}' $path_file | tr -d '[:space:]')

mkdir build
cd build
cp ../SSNQ.path .
cp ../ssnq-init-conf.sh .
cp ../ssnq-build-hdb-maps.sh .
ln -s -f ../spdk-nvme.so spdk-nvme.so
ln -s -f ../sci-spdk-nvme-q.so sci-spdk-nvme-q.so
ln -s -f ../ssnq-build-hdb-maps-single-dev.bin ssnq-build-hdb-maps.bin
ln -s -f $sci_dir/libsyscall_intercept.so libsyscall_intercept.so.0

chmod +x ssnq-init-conf.sh
chmod +x ssnq-build-hdb-maps.sh
chmod +x spdk-nvme.so
chmod +x ssnq-build-hdb-maps.bin
#chmod +x libsyscall_intercept.so.0


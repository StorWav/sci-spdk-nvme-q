# SSNQ: SCI-SPDK-NVMe-Q - System Call Interception With SPDK/NVMe Drivers For Kdb+/Q
SSNQ is a sophisticated library designed to intercept system calls from Kdb+/Q and redirect them to SPDK/NVMe backend interfaces, thereby achieving superior I/O performance without necessitating any modifications to existing applications. The source code provides a demonstration of how to intercept syscalls associated with Kdb+/Q. In essence, several system calls from Kdb+/Q, particularly those related to mmap, are intercepted and rerouted to corresponding SPDK/NVMe APIs.

Herein, you'll find complete procedures for building and running an SSNQ-enabled Kdb+/Q. For more technical details, please visit my Medium article [Turbocharging Kdb+ HDB: Unleashing the Power of High-Speed Mirroring for Optimal Performance](https://medium.com/@colinzhu/turbocharging-kdb-hdb-unleashing-the-power-of-high-speed-mirroring-for-optimal-performance-7f9df2557c02)

## How To Build SSNQ And Run SSNQ-Enabled Kdb+/Q
The following procedures have been verified on Ubuntu 22.04.2. Kindly adhere to these exact procedures as some steps necessitate "root" permissions and will require "sudo" for accurate execution.

### 1. Install Ubuntu Development Packages
```
sudo apt-get install build-essential pkg-config libcapstone-dev pandoc clang git cmake libxxhash-dev
```

### 2. Install syscall_intercept Library
Unless specified otherwise, all operations are performed under the user directory, in my case, ```/home/czhu```, so ```cd ~/``` is equivalent to ```cd /home/czhu```.
```
cd ~/
git clone https://github.com/pmem/syscall_intercept.git
cd syscall_intercept
mkdir build
cd build/
cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang
make
sudo make install
```

### 3. Enable 1G Hugepage and Unlimited mem_lock
* Check if ```pdpe1gb``` is supported by reviewing ```/proc/cpuinfo```.
* As a root user, edit ```/etc/default/grub``` and modify ```GRUB_CMDLINE_LINUX=``` to ```GRUB_CMDLINE_LINUX="default_hugepagesz=1G hugepagesz=1G"```.
* As a root user, update grub with ```sudo update-grub```.
* As a root user, set unlimited memlock for "root", "spdk", and users (in my case "czhu") by adding the following lines to ```/etc/security/limits.conf:```:
```
spdk     hard   memlock           unlimited
spdk     soft   memlock           unlimited
root     hard   memlock           unlimited
root     soft   memlock           unlimited
czhu     hard   memlock           unlimited
czhu     soft   memlock           unlimited
```
* Reboot the server to apply the above settings.

### 4. Install SPDK
```
cd ~/
git clone https://github.com/spdk/spdk
cd spdk
git submodule update --init
sudo ./scripts/pkgdep.sh
cp dpdk/config/rte_config.h dpdk/config/rte_config.h_backup
sed -i 's/\(#define RTE_MAX_MEM_MB_PER_LIST \)[0-9]*/\1262144/; s/\(#define RTE_MAX_MEM_MB_PER_TYPE \)[0-9]*/\1524288/' dpdk/config/rte_config.h
./configure
make
```

### 5. Build SSNQ Libraries and Binaries
* Retrieve SSNQ sources.
```
cd ~/
git clone https://github.com/StorWav/ssnq.git
cd ssnq
```
* Make sure that ```SSNQ.path``` has the correct paths. It is likely that you'll need to modify ```Q_LICENSE``` and ```SPDK_ROOT_DIR```. ```Q_LICENSE``` should point to the path where license files ```kc.lic``` and ```q.k``` are located.
```
Q_LICENSE       := /home/czhu/q
SPDK_ROOT_DIR   := /home/czhu/spdk
SCI_DIR         := /usr/local/lib
SSNQ_CONF       := SSNQ.conf
SSNQ_HDB_MAPS   := SSNQ.hdb.maps
SSNQ_FILE_LIST  := /tmp/.ssnq_hdb_files
SSNQ_NVME_SN    := /tmp/.ssnq_nvme_sn
```
* Build and Install:
```
make
sh ssnq-install.sh
cd build
```
* Generate Initial Configuration file ```SSNQ.conf``` by running ```./ssnq-init-conf.sh```.
* Add HDB path into the configuration: edit ```SSNQ.conf``` to add the path to the actual HDB, in my case it is ```hdbroot=/home/czhu/q/hdb```.
* Mirror HDB data and generate SSNQ HDB maps ```SSNQ.hdb.maps``` by running ```sudo ./ssnq-build-hdb-maps.sh```.
* If SPDK was updated and rebuilt, SSNQ must be rebuilt with ```make```.
* All SSNQ-related configuration files, scripts, and binaries reside in the ```ssnq/build``` directory. This directory should comprise the following elements:
```
ssnq/build
├── libsyscall_intercept.so.0 -> /usr/local/lib/libsyscall_intercept.so
├── sci-spdk-nvme-q.so -> ../sci-spdk-nvme-q.so
├── spdk-nvme.so -> ../spdk-nvme.so
├── ssnq-build-hdb-maps.bin -> ../ssnq-build-hdb-maps-single-dev.bin
├── ssnq-build-hdb-maps.sh
├── SSNQ.conf
├── SSNQ.hdb.maps
├── ssnq-init-conf.sh
└── SSNQ.path
```

### 6. Run SSNQ-Enabled Kdb+/Q
* As a root user, load SPDK NVMe drives:
```
sudo HUGEMEM=40000 /home/czhu/spdk/scripts/setup.sh
```
* In the ```ssnq/build``` directory, in my case, ```/home/czhu/ssnq/build```, load Kdb+/Q like this:
```
sudo LD_LIBRARY_PATH=. LD_PRELOAD=sci-spdk-nvme-q.so rlwrap /home/czhu/q/l64/q -s 24 "$@"
```
* To evaluate the impact of disk I/O performance, it is recommended to drop cache before each run:
```
echo 3 | sudo tee /proc/sys/vm/drop_caches
```

For questions and issues, please email me at czhu@nexnt.com

Enjoy your exploration!

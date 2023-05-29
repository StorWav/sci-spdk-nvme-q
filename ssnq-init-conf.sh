#!/bin/sh

path_file="SSNQ.path"
conf_file=$(awk -v token="SSNQ_CONF" -F ':=' '$1 ~ token {print $2}' $path_file | tr -d '[:space:]')
spdk_path=$(awk -v token="SPDK_ROOT_DIR" -F ':=' '$1 ~ token {print $2}' $path_file | tr -d '[:space:]')
nvme_sn_tmp=$(awk -v token="SSNQ_NVME_SN" -F ':=' '$1 ~ token {print $2}' $path_file | tr -d '[:space:]')
disk_number=1
# for now, always use namespace 1
ns=1

# Check if the file exists
if [ -e "$conf_file" ]; then
    echo "Warning: The file '$conf_file' already exists. Exiting."
    exit 1
fi

rm -rf $nvme_sn_tmp

# 300-400G buffer might be necessary if we want to load entire "quotes" and "trades" tables
# max_mmap_cnt=1310
# max_scratch_cnt=496

# Add default io configurations
echo "mmap_unit_size=104857600" >> "$conf_file"
echo "max_mmap_cnt=128" >> "$conf_file"
echo "scratch_unit_size=536870912" >> "$conf_file"
echo "max_scratch_cnt=40" >> "$conf_file"
echo "submit_chunk_size=104857600" >> "$conf_file"
echo "" >> "$conf_file"

# Add nvme drives available from SPDK
echo "INFO: Load SPDK NVMe drives."
sudo $spdk_path/scripts/setup.sh
echo "INFO: Identify available SPDK NVMe drives."
sudo $spdk_path/build/examples/identify | grep "Serial Number:" | awk -F " " {'print $3'} > $nvme_sn_tmp
echo "INFO: Unload SPDK NVMe drives."
sudo $spdk_path/scripts/setup.sh reset

while read -r serial; do
    for device_path in /sys/block/nvme*n${ns}/device; do
        device_serial_file="${device_path}/serial"
        device_address_file="${device_path}/address"

        if [ -e "$device_serial_file" ] && [ -e "$device_address_file" ]; then
            device_serial=$(cat "$device_serial_file" | sed 's/[[:space:]]*$//')

            if [ "$serial" = "$device_serial" ]; then
                device_address=$(cat "$device_address_file")
				echo "disk$(printf "%03d"   ${disk_number})   $serial   $device_address   $ns" >> "$conf_file"
				disk_number=$((disk_number + 1))

				# Check next serial number in $nvme_sn_tmp
				break
            fi
        fi
    done
done < "$nvme_sn_tmp"

# Add hdbroot
echo "" >> "$conf_file"
echo "hdbroot=" >> "$conf_file"

if [ "$?" = "0" ]; then
	echo "*************************************************************"
	echo "* Initialization done.                                      *"
	echo "* Please add HDB path to line 'hdbroot=' in $conf_file file. *"
	echo "*************************************************************"
	echo
fi

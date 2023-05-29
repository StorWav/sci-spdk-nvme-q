#!/bin/bash

path_file="SSNQ.path"
ssnq_conf=$(awk -v token="SSNQ_CONF" -F ':=' '$1 ~ token {print $2}' $path_file | tr -d '[:space:]')
ssnq_list_file=$(awk -v token="SSNQ_FILE_LIST" -F ':=' '$1 ~ token {print $2}' $path_file | tr -d '[:space:]')
ssnq_maps=$(awk -v token="SSNQ_HDB_MAPS	" -F ':=' '$1 ~ token {print $2}' $path_file | tr -d '[:space:]')
spdk_dir=$(awk -v token="SPDK_ROOT_DIR	" -F ':=' '$1 ~ token {print $2}' $path_file | tr -d '[:space:]')
build_hdb_maps_bin=ssnq-build-hdb-maps.bin

chmod -x $build_hdb_maps_bin

# Ensure conf file exist
if [ ! -f "$ssnq_conf" ]; then
	echo "Error: $ssnq_conf file does not exist."
	exit 1
fi

# Function to extract values
extract_values() {
    local input_file="$1"
    local prefix="$2"
    grep -v '^#' "$input_file" | grep "^$prefix" | sed "s/^$prefix//" | grep -v '^$' | sort -u
}
	
# Check if both files exist
if [ -f "$ssnq_conf" ] && [ -f "$ssnq_maps" ]; then
	
	# Extract and store values from both files
	disk_A=$(extract_values "$ssnq_conf" "disk")
	disk_B=$(extract_values "$ssnq_maps" "disk")

	# Compare the extracted contents and print the result
	if [ "$disk_A" == "$disk_B" ]; then
    	echo "INFO: settings in $ssnq_conf consistent with $ssnq_map"
	else
    	echo "ERROR: settins in $ssnq_conf mismatch with $ssnq_maps"
    	exit 1
	fi
fi

disk_number=0

# Generate hdb file list
# Loop through lines starting with "hdbroot=" in the input file
rm -rf $ssnq_list_file
while read -r line; do
    key="${line%%=*}"
    if [ "$key" = "hdbroot" ]; then
        rootdir="${line#*=}"

        rootdir_name=$(echo "$rootdir" | tr '/' '_')

        # Check if the par.txt file exists in the rootdir
        if [ -f "$rootdir/par.txt" ]; then
            while read -r parline; do
            	if [[ $parline =~ [^[:space:]] ]]; then
	                first_char=$(echo "$parline" | cut -c1)
    	            first_two_chars=$(echo "$parline" | cut -c1-2)

        	        if [ "$first_char" = "/" ]; then
            	        parlinedir="$parline"
                	elif [ "$first_char" = "." ] || [ "$first_two_chars" = ".." ]; then
                    	parlinedir="$rootdir/$parline"
             	   fi

	                # Find all files in the parlinedir and print them
            	    if [ -d "$parlinedir" ]; then
						parline_files=$(find "$parlinedir" -type f -exec realpath {} \;)
						for file in $parline_files; do
							if [ -f "$file" ]; then
								real_file_path=$(realpath "$file")
								echo "$disk_number  $real_file_path" >> "$ssnq_list_file"
							fi
						done
						disk_number=$((disk_number + 1))
					
                	fi
                fi
            done < "$rootdir/par.txt"
        else
			#find "$rootdir" -type f -exec realpath {} \; >> "$ssnq_list_file"
			for dir in $(find $rootdir -maxdepth 1 -type d)
			do
				# Skip if the directory is the root folder itself
				if [ "$dir" = "$rootdir" ]
				then
	    			continue
				fi

				# Iterate over files in the directory
				for file in $(find $dir -type f)
				do
				# Echo disk index and filename to the destination file
				echo "$disk_number $file" >> "$ssnq_list_file"
				done

				# Increment disk index
				disk_number=$((disk_number+1))
			done
        fi
    fi
done < "$ssnq_conf"

if [ -e "$ssnq_list_file" ] && [ -s "$ssnq_list_file" ]; then
    echo "INFO: $ssnq_list_file generated successfully."
    chmod a-w $ssnq_list_file
    
    echo "INFO: Unload SPDK NVMe drives."
    sudo $spdk_dir/scripts/setup.sh reset
    
    echo "INFO: Copying HDB data and building $ssnq_maps ...... "
    chmod +x $build_hdb_maps_bin
    ./$build_hdb_maps_bin
    chmod -x $build_hdb_maps_bin
    
    if [ "$?" = "0" ]; then
    	echo "Done!"
    else
    	echo "Failed!"
    fi
else
    echo "ERROR: $ssnq_list_file does not exist or is empty."
	rm -rf $ssnq_list_file
fi

#!/bin/bash

echo "#!/bin/bash" > "/etc/udev/scripts/protmount2-$2.sh"
echo "mkdir /media/$1" >> "/etc/udev/scripts/protmount2-$2.sh"
echo "chmod 777 /media/$1" >> "/etc/udev/scripts/protmount2-$2.sh"
echo "/bin/mount /dev/$1 -o ro,noatime /media/$1" >> "/etc/udev/scripts/protmount2-$2.sh"
chmod +x "/etc/udev/scripts/protmount2-$2.sh"


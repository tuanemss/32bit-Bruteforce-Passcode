#!/bin/sh
echo "32-bit Bruteforce Ramdisk"
echo "--------------------------------"
echo "RAMDISK SETUP: STARTING" > /dev/console

# Start SSHD
echo "RAMDISK SETUP: STARTING SSHD" > /dev/console
/sbin/sshd

# Run restored_external (background)
echo "RAMDISK SETUP: COMPLETE" > /dev/console
/usr/local/bin/restored_external.sshrd > /dev/console &
sleep 2

# Check for mount.sh
if [ -x /bin/mount.sh ]; then
    /bin/mount.sh > /dev/console
fi

# Run Bruteforce
/usr/bin/bruteforce -u > /dev/console

echo "Fixing disabled"

cd /mnt2/mobile/Library/Preferences/
for file in com.apple.springboard.plist.???????; do
    if [ -f "$file" ]; then
        rm "$file" > /dev/null
    fi
done
# mv /mnt2/mobile/Library/Preferences/com.apple.springboard.plist /mnt2/mobile/Library/Preferences/com.apple.springboard.plist.bak > /dev/null
# rm /mnt2/mobile/Library/Preferences/com.apple.springboard.plist > /dev/null
# rm /mnt2/mobile/Library/SpringBoard/LockoutStateJournal.plist > /dev/null

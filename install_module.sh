#!/bin/sh
#set -x
# WARNING: this script doesn't check for errors, so you have to enhance it in case any of the commands
# below fail.
rmmod sys_cpenc.ko
ret="$?"
if [ "$ret" -eq "1" ]; then
    echo "Module is removed..Loading now "
fi

insmod sys_cpenc.ko
ret="$?"
if [ "$ret" -ne "0" ]; then
  echo "Sorry, cannot load module, Error = "$ret" "
  exit 1
fi
lsmod

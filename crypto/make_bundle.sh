#!/bin/bash
unzip -d ipsw $1
find ipsw -type f -exec ./get_key.sh {} \;
rm -rf ipsw


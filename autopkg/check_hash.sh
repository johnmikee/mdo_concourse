#!/bin/sh

if [[ $(shasum -a 256 $1 | cut -f 1 -d' ') == "$2" ]]; then
    echo "sha matches for $1"
    exit 0
else
    echo "sha does not match for $1"
    exit 1
fi

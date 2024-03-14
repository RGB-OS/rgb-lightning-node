#!/bin/sh

# Use the first argument specifically for `mount-s3` and then shift it out
mount-s3 $1 /s3
shift

# Now, pass the remaining arguments to /usr/bin/rgb-lightning-node
/usr/bin/rgb-lightning-node $@

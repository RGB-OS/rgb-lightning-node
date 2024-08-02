#!/bin/sh

# Use the first argument specifically for `mount-s3` and then shift it out
3fs $1 /s3 -o iam_role=auto -o ecs -o endpoint=us-east-2
shift

# Now, pass the remaining arguments to /usr/bin/rgb-lightning-node
/usr/bin/rgb-lightning-node $@

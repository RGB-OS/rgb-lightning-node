#!/bin/bash

# Use the first argument specifically for `mount-s3` and then shift it out
s3fs $1 /s3 -o iam_role=auto -o ecs -o endpoint=us-east-2
VOLUME_ID=$2
USER_ID=$3
NODE_ID=$4
INSTANCE_ID=$(curl http://169.254.169.254/latest/meta-data/instance-id)

# Find an available device name
AVAILABLE_DEVICE=""
for device in {f..z}; do
    if ! lsblk | grep -q "/dev/xvd$device"; then
        AVAILABLE_DEVICE="/dev/xvd$device"
        break
    fi
done

if [ -z "$AVAILABLE_DEVICE" ]; then
    echo "Error: No available device name found."
    exit 1
fi

# Detach the volume if it's already attached
ATTACHMENT_STATE=$(aws ec2 describe-volumes --volume-ids $VOLUME_ID --query 'Volumes[0].Attachments[0].State' --output text)
if [ "$ATTACHMENT_STATE" == "attached" ]; then
    PREVIOUS_INSTANCE_ID=$(aws ec2 describe-volumes --volume-ids $VOLUME_ID --query 'Volumes[0].Attachments[0].InstanceId' --output text)
    if [ "$PREVIOUS_INSTANCE_ID" != "$INSTANCE_ID" ]; then
        echo "Detaching volume from previous instance $PREVIOUS_INSTANCE_ID"
        aws ec2 detach-volume --volume-id $VOLUME_ID
        while [ "$(aws ec2 describe-volumes --volume-ids $VOLUME_ID --query 'Volumes[0].State' --output text)" != "available" ]; do
            sleep 1
        done
    fi
fi

# Attach the volume to the current instance
echo "Attaching volume $VOLUME_ID to instance $INSTANCE_ID as $AVAILABLE_DEVICE"
aws ec2 attach-volume --volume-id $VOLUME_ID --instance-id $INSTANCE_ID --device $AVAILABLE_DEVICE
while [ "$(aws ec2 describe-volumes --volume-ids $VOLUME_ID --query 'Volumes[0].Attachments[0].State' --output text)" != "attached" ]; do
    sleep 1
done

# Wait for the device to be available on the instance
while [ ! -e $AVAILABLE_DEVICE ]; do
    echo "Waiting for device $AVAILABLE_DEVICE to be available..."
    sleep 1
done

# Mount the volume
if ! mount | grep /mnt/ebs-${USER_ID}-${NODE_ID}; then
    echo "Mounting volume $VOLUME_ID to /mnt/ebs-${USER_ID}-${NODE_ID}"
    mkdir -p /mnt/ebs-${USER_ID}-${NODE_ID}
    mount $AVAILABLE_DEVICE /mnt/ebs-${USER_ID}-${NODE_ID}
fi

shift 4
# Now, pass the remaining arguments to /usr/bin/rgb-lightning-node
/usr/bin/rgb-lightning-node $@

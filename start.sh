#!/bin/bash

# Use the first argument specifically for `mount-s3` and then shift it out
s3fs $1 /s3 -o iam_role=auto -o ecs -o endpoint=us-east-2
VOLUME_ID=$2
USER_ID=$3
NODE_ID=$4
INSTANCE_ID=$(curl http://169.254.169.254/latest/meta-data/instance-id)

# Step 1: Find the last used NVMe device number
LAST_NVME_DEVICE_NUM=0
for i in {1..26}; do
    # Check for the presence of NVMe devices, but skip nvme0n1 (system disk)
    if lsblk | grep -q "nvme${i}n1" && [ "$i" -ne 0 ]; then
        LAST_NVME_DEVICE_NUM=$i
    fi
done

if [ $LAST_NVME_DEVICE_NUM -eq 0 ]; then
    echo "No additional NVMe devices found beyond nvme0n1 (system disk)."
else
    echo "Last used NVMe device: /dev/nvme${LAST_NVME_DEVICE_NUM}n1"
fi

# Step 2: Find the next available NVMe device number
NEXT_NVME_DEVICE_NUM=$((LAST_NVME_DEVICE_NUM + 1))
AVAILABLE_NVME_DEVICE="/dev/nvme${NEXT_NVME_DEVICE_NUM}n1"

echo "Next available NVMe device: $AVAILABLE_NVME_DEVICE"

AVAILABLE_DEVICE=""
# Get all attached devices in one line, and split into individual device names
ATTACHED_DEVICES=$(aws ec2 describe-volumes --filters Name=attachment.instance-id,Values=$INSTANCE_ID Name=attachment.status,Values=attached,attaching --query 'Volumes[].Attachments[].Device' --output text | tr '\t' '\n')

for device in {f..p}; do
    DEVICE_NAME="/dev/xvd$device"
    
    # Log the device check
    echo "Checking $DEVICE_NAME..."

    # Check if the device name is in use either locally or in the list from AWS
    if ! lsblk | grep -q "$DEVICE_NAME" && ! echo "$ATTACHED_DEVICES" | grep -q "$DEVICE_NAME"; then
        AVAILABLE_DEVICE="$DEVICE_NAME"
        echo "Available device: $AVAILABLE_DEVICE"
        break
    else
        echo "$DEVICE_NAME is in use or unavailable."
    fi
done

if [ -z "$AVAILABLE_DEVICE" ]; then
    echo "Error: No available device name found."
    exit 1
fi

echo "Next available traditional device: $AVAILABLE_DEVICE"

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
	# Attach the volume to the current instance
        echo "Attaching volume $VOLUME_ID to instance $INSTANCE_ID as $AVAILABLE_DEVICE"
        aws ec2 attach-volume --volume-id $VOLUME_ID --instance-id $INSTANCE_ID --device $AVAILABLE_DEVICE
        while [ "$(aws ec2 describe-volumes --volume-ids $VOLUME_ID --query 'Volumes[0].Attachments[0].State' --output text)" != "attached" ]; do
            sleep 1
        done
    fi
else
    # Attach the volume to the current instance
    echo "Attaching volume $VOLUME_ID to instance $INSTANCE_ID as $AVAILABLE_DEVICE"
    aws ec2 attach-volume --volume-id $VOLUME_ID --instance-id $INSTANCE_ID --device $AVAILABLE_DEVICE
    while [ "$(aws ec2 describe-volumes --volume-ids $VOLUME_ID --query 'Volumes[0].Attachments[0].State' --output text)" != "attached" ]; do
        sleep 1
    done
fi

## Wait for the NVMe device to be available
NVME_DEVICE=""
while [ -z "$NVME_DEVICE" ]; do
    # Use lsblk to list all NVMe devices, filtering out the root device (nvme0n1)
    for device in $(lsblk -o NAME,TYPE | grep 'nvme' | grep -v 'nvme0n1' | awk '{print "/dev/"$1}'); do
        # Get the serial number for the NVMe device
        SN=$(nvme id-ctrl -v $device | grep 'sn' | awk '{print $3}')  # Extract the serial number
        echo $SN
        if [[ $SN == vol* ]]; then
            # Convert the SN to EBS volume ID format by inserting a hyphen
            VOLUME_NVME_ID="${SN:0:3}-${SN:3}"
            if [[ $VOLUME_NVME_ID == $VOLUME_ID ]]; then
                echo "Found NVMe device: $device with Volume ID: $VOLUME_ID"
                NVME_DEVICE=$device
                break
            fi
        fi
    done
    if [ -z "$NVME_DEVICE" ]; then
        echo "Waiting for NVMe device to be available..."
        sleep 1
    fi
done

# Mount the volume
if ! mount | grep /mnt/ebs-${USER_ID}-${NODE_ID}; then
    # Check if the device already has a filesystem
    FS_TYPE=$(blkid -o value -s TYPE $NVME_DEVICE)
    
    if [ -z "$FS_TYPE" ]; then
        echo "No filesystem detected on $NVME_DEVICE. Creating ext4 filesystem."
        mkfs.ext4 $NVME_DEVICE
    else
        echo "Filesystem $FS_TYPE already exists on $NVME_DEVICE. Skipping mkfs."
    fi

    echo "Mounting volume $VOLUME_ID to /mnt/ebs-${USER_ID}-${NODE_ID}"
    mkdir -p /mnt/ebs-${USER_ID}-${NODE_ID}
    mount $NVME_DEVICE /mnt/ebs-${USER_ID}-${NODE_ID}
fi

echo 'Volume mounted!'

shift 4
# Now, pass the remaining arguments to /usr/bin/rgb-lightning-node
/usr/bin/rgb-lightning-node $@

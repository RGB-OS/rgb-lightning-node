#!/bin/bash

# Use the first argument specifically for `mount-s3` and then shift it out
3fs $1 /s3 -o iam_role=auto -o ecs -o endpoint=us-east-2
VOLUME_ID=$2

INSTANCE_ID=$(curl http://169.254.169.254/latest/meta-data/instance-id)

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
echo "Attaching volume $VOLUME_ID to instance $INSTANCE_ID"
aws ec2 attach-volume --volume-id $VOLUME_ID --instance-id $INSTANCE_ID --device /dev/xvdh
while [ "$(aws ec2 describe-volumes --volume-ids $VOLUME_ID --query 'Volumes[0].Attachments[0].State' --output text)" != "attached" ]; do
    sleep 1
done

# Mount the volume
if ! mount | grep /mnt/ebs; then
    echo "Mounting volume $VOLUME_ID to /mnt/ebs-${var.user_id}-${each.key}"
    mkdir -p /mnt/ebs-${var.user_id}-${each.key}
    mount /dev/xvdh /mnt/ebs-${var.user_id}-${each.key}
fi

shift 2
# Now, pass the remaining arguments to /usr/bin/rgb-lightning-node
/usr/bin/rgb-lightning-node $@

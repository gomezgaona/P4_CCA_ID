#!/bin/bash

# Define remote destination
REMOTE_USER="root"
REMOTE_HOST="172.168.1.2"
REMOTE_DIR="/root/P4_CCA_ID"

# Ensure SSH key authentication is set up (optional)
SSH_KEY="~/.ssh/id_rsa"  # Change this if using a different key

echo "Sending all files and directories from $(pwd) to ${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}..."

# Execute SCP command
scp -r ./* "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}"

# Check if SCP was successful
if [ $? -eq 0 ]; then
    echo "All files and directories have been successfully transferred!"
else
    echo "Error: File transfer failed."
fi
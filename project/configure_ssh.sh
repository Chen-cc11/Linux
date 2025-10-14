#!/bin/bash
# First, you need to create a `.ssh` directory in the  user’s home directory
# and generate a new SSH key pair.

mkdir -p ~/.ssh
ssh-keygen -t rsa -b 4096 -C "user@localhost"

# Then, add the newly generated public key to the `authorized_keys` file

cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Restart the SSH service
sudo service ssh restart

# Test SSH
ssh user@localhost
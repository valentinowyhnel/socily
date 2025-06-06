#!/bin/bash
set -e

# Activate virtual environment
cd /home/cowrie/cowrie
. .env/bin/activate

# Start Cowrie
# Using bin/cowrie instead of cowrie command directly as per cowrie docs for foreground
# The -n option keeps cowrie in the foreground, which is necessary for Docker containers
exec bin/cowrie start -n

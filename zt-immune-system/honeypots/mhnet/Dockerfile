# Generic Dockerfile for mhnet honeypot
# This Dockerfile provides a basic structure.
# The actual honeypot setup and execution logic should be implemented
# in the mhnet_setup.sh script.

# 1. Start from a basic OS image
FROM debian:bullseye-slim

# Install any common dependencies that most honeypots might need.
# sudo is included in case the setup script needs to elevate privileges temporarily,
# though it's generally better to set up permissions correctly.
RUN apt-get update && apt-get install -y \
    sudo \
    --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

# 2. Create a non-root user
RUN groupadd -r honeypot_user && \
    useradd -r -g honeypot_user -d /home/honeypot_user -s /bin/bash -c "Honeypot User" honeypot_user && \
    mkdir -p /home/honeypot_user && \
    chown -R honeypot_user:honeypot_user /home/honeypot_user

# Allow honeypot_user to run sudo commands without a password (use with caution)
# This might be needed by some honeypot setup scripts.
# Consider removing or restricting this if not strictly necessary for your honeypot.
RUN echo "honeypot_user ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# 3. Set up a working directory
WORKDIR /opt/mhnet

# 4. Copy the mhnet_setup.sh script and ensure it's executable
COPY mhnet_setup.sh /opt/mhnet/mhnet_setup.sh
RUN chmod +x /opt/mhnet/mhnet_setup.sh && \
    chown honeypot_user:honeypot_user /opt/mhnet/mhnet_setup.sh

# 5. Switch to the honeypot_user
USER honeypot_user

# 6. Set mhnet_setup.sh as the ENTRYPOINT
ENTRYPOINT ["/opt/mhnet/mhnet_setup.sh"]

# Optional: Define a CMD if you want to pass default arguments to the entrypoint
# CMD ["--default-arg"]

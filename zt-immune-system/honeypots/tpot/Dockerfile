# Dockerfile for T-Pot environment
# This Dockerfile prepares a basic environment. The actual T-Pot deployment,
# setup, and execution logic should be implemented in the start.sh script,
# potentially using configurations from config.yaml.

# 1. Start from a basic OS image
FROM debian:bullseye-slim

# 2. Install necessary dependencies
# These are common dependencies; T-Pot or its components might need more.
# Adjust as necessary.
RUN apt-get update && apt-get install -y \
    git \
    curl \
    sudo \
    --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

# 3. Create a non-root user tpot_user
RUN groupadd -r tpot_user && \
    useradd -r -g tpot_user -d /home/tpot_user -s /bin/bash -c "T-Pot User" tpot_user && \
    mkdir -p /home/tpot_user && \
    chown -R tpot_user:tpot_user /home/tpot_user

# Optionally, grant sudo access if start.sh needs it.
# Consider the security implications.
RUN echo "tpot_user ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# 4. Set up a working directory
WORKDIR /opt/tpot

# 5. Copy config.yaml and start.sh
COPY config.yaml /opt/tpot/config.yaml
COPY start.sh /opt/tpot/start.sh

# Ensure config.yaml is owned by tpot_user
RUN chown tpot_user:tpot_user /opt/tpot/config.yaml

# 6. Ensure start.sh is executable and owned by tpot_user
RUN chmod +x /opt/tpot/start.sh && \
    chown tpot_user:tpot_user /opt/tpot/start.sh

# 7. Switch to tpot_user
USER tpot_user

# 8. Set /opt/tpot/start.sh as the ENTRYPOINT
ENTRYPOINT ["/opt/tpot/start.sh"]

# Optional: Define a CMD if you want to pass default arguments to the entrypoint
# CMD ["--default-tpot-arg"]

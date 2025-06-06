# 1. Start from a suitable base image
FROM python:3.9-slim

# 2. Install necessary dependencies
RUN apt-get update && apt-get install -y \
    git \
    virtualenv \
    libssl-dev \
    libffi-dev \
    build-essential \
    python3-dev \
    authbind \
    --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

# 3. Create a non-root user cowrie
RUN groupadd -r cowrie && useradd -r -g cowrie -d /home/cowrie -s /sbin/nologin -c "Cowrie Honeypot" cowrie
RUN mkdir -p /home/cowrie && chown -R cowrie:cowrie /home/cowrie

# 4. Switch to the cowrie user
USER cowrie

# 5. Set up a working directory
WORKDIR /home/cowrie

# 6. Clone the official Cowrie git repository
RUN git clone --branch v2.6.1 https://github.com/cowrie/cowrie.git cowrie
WORKDIR /home/cowrie/cowrie

# 7. Create and activate a Python virtual environment
RUN python3 -m venv .env
# Note: Activation is handled by sourcing in the entrypoint/cmd, not directly here

# 8. Install Python dependencies
RUN .env/bin/pip install --no-cache-dir -r requirements.txt

# 9. Copy the cowrie.cfg into the container
# This file is expected to be in the build context
COPY cowrie.cfg /home/cowrie/cowrie/etc/cowrie.cfg.dist

# 10. Expose ports 2222 (SSH) and 2223 (Telnet)
EXPOSE 2222
EXPOSE 2223

# 11. Set an appropriate entrypoint or command to run Cowrie
# Assume start_cowrie.sh will be in the Cowrie home directory (/home/cowrie/cowrie)
# and will handle activating the venv and starting cowrie
COPY start_cowrie.sh /home/cowrie/cowrie/start_cowrie.sh
RUN chmod +x /home/cowrie/cowrie/start_cowrie.sh
ENTRYPOINT ["/home/cowrie/cowrie/start_cowrie.sh"]

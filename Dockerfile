FROM alpine:3.20

# Install required tools
RUN apk add --no-cache \
    bash \
    git \
    python3 \
    py3-pip \
    ca-certificates

# Create working directory
WORKDIR /securegitx

# Copy SecureGitX files
COPY bin/securegitx.sh /usr/local/bin/securegitx
COPY wrappers/securegitx_wrapper.py /usr/local/bin/securegitx_wrapper.py

# Make executable
RUN chmod +x /usr/local/bin/securegitx

# Default command
ENTRYPOINT ["securegitx"]

FROM alpine:latest

# Copy your pre-built Nakama binary named "inspo"
COPY inspo /inspo/inspo

# Copy your data (modules, configs, etc.)
COPY ./data /inspo/data

# Run your Nakama binary
ENTRYPOINT ["/inspo/inspo"]

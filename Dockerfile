# Build stage
FROM golang:1.24.2-alpine AS builder

WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o /inspo

# Final stage
FROM alpine:latest

WORKDIR /inspo

# Copy the binary from builder
COPY --from=builder /inspo .

# Make the binary executable
RUN chmod +x inspo

# Expose the ports your application uses
EXPOSE 7349 7350 7351

# Command to run the executable
CMD ["./inspo"]

# Build stage
FROM rust:1.75-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# Copy source code
COPY . .

# Build the release binary
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy the compiled binary from builder
COPY --from=builder /app/target/release/url-shortener /usr/local/bin/

# Create a non-root user
RUN useradd -r -s /bin/false appuser
USER appuser

# Expose the default port
EXPOSE 8080

# Set default environment variables
ENV HOST=0.0.0.0
ENV PORT=8080

# Run the application
CMD ["url-shortener"]

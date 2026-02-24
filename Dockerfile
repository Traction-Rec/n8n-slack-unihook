# Build stage
FROM rust:1.93-slim-bookworm AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy the source code
COPY Cargo.toml Cargo.lock* ./
COPY src ./src

# Build the release binary
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy the binary from the build stage
COPY --from=builder /app/target/release/n8n-unihook /usr/local/bin/n8n-unihook

# Create a non-root user and a writable data directory for the SQLite database
RUN useradd --create-home --shell /bin/bash appuser \
    && mkdir -p /data \
    && chown appuser:appuser /data
USER appuser

# Default environment variables
ENV LISTEN_ADDR=0.0.0.0:3000
ENV REFRESH_INTERVAL_SECS=60
ENV RUST_LOG=n8n_unihook=info

# Expose the default port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Run the application
CMD ["n8n-unihook"]

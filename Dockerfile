# Companion — single-file server image.
#
# Layout assumed by the image (see src/companion.py for the full split):
#   CONFIG  — optional. Bind-mount /etc/companion/config.json:ro, or set
#             COMPANION_* env vars (env wins per-key). Pure-env runs are fine.
#   STATE   — required. /data is the writable volume holding the client DB
#             (servers/<name>/clients.json). Survives container restarts.
#
# First-time bootstrap (no admin in state yet):
#   docker run --rm -v companion-data:/data \
#     -e COMPANION_BOOTSTRAP_ADMIN=admin:s3cret \
#     -p 8080:8080 companion
#
# Subsequent runs reuse the admin already in the volume (the env var is ignored
# once an admin exists), so it is safe to leave set.
#
# Managing the container with containerctl:
#   containerctl ps
#   containerctl logs <id> -f
#   containerctl exec <id> python /app/companion.py rotate --server default

FROM python:3.12-alpine

WORKDIR /app

# Copy the built single-file distribution (PDF.js inlined by build.py).
COPY companion.py /app/companion.py

ENV COMPANION_STATE_DIR=/data \
    COMPANION_CONFIG=/etc/companion/config.json \
    COMPANION_PORT=8080

VOLUME ["/data"]
EXPOSE 8080

CMD ["python", "/app/companion.py", "server"]

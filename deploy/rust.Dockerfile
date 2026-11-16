# Rust profile image. Dependencies and toolchain are prebuilt in the image.
FROM rust:1.83-alpine
# Numeric user for hosts that cannot supply a uid (native Windows Getuid is -1).
# Unix hosts override this with --user <host-uid>:<host-gid>.
RUN apk add --no-cache musl-dev && adduser -D -u 65532 -H agt
CMD ["sleep", "infinity"]

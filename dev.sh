#!/bin/sh
exec podman run --rm -it --name anonify-test \
  --cap-add NET_ADMIN --cap-add SYS_ADMIN --cap-add NET_RAW \
  -v "$HOME/Projects/anonify":/anonify:Z \
  -v anonify-target:/target -v anonify-cargo:/root/.cargo \
  -e CARGO_TARGET_DIR=/target -w /anonify \
  anonify-dev bash

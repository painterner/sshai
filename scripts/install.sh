#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo_root"

cargo install --locked --path crates/sshai-cli --force

if [[ $(uname -s) == Linux ]]; then
  host_target=$(rustc -vV | sed -n 's/^host: //p')
  case "$host_target" in
    x86_64-unknown-linux-gnu)
      rustflags_name=CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS
      ;;
    aarch64-unknown-linux-gnu)
      rustflags_name=CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS
      ;;
    *)
      echo "sshai: no portable static worker recipe for $host_target" >&2
      exit 1
      ;;
  esac

  env "$rustflags_name=-C target-feature=+crt-static" \
    cargo build --locked --release --target "$host_target" --bin sshai-worker
  cargo_bin_dir=${CARGO_HOME:-$HOME/.cargo}/bin
  install -d "$cargo_bin_dir"
  install -m 755 \
    "target/$host_target/release/sshai-worker" \
    "$cargo_bin_dir/sshai-worker-static"
  echo "installed portable worker: $cargo_bin_dir/sshai-worker-static"
fi

if [[ ${1:-} == --with-termm ]]; then
  cargo install --locked --path termm --force
fi

#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
output=${1:-"$script_dir/dist/casa1-tetris.exe"}

mkdir -p "$(dirname "$output")"

set -- \
  -target x86_64-windows-gnu \
  -std=c11 \
  -O1 \
  -DUNICODE \
  -D_UNICODE \
  -ffreestanding \
  -fno-stack-protector \
  -fno-builtin \
  -fno-vectorize \
  -fno-slp-vectorize \
  -fno-sanitize=undefined \
  -fno-asynchronous-unwind-tables \
  -fno-unwind-tables \
  -falign-functions=1 \
  -falign-jumps=1 \
  -falign-labels=1 \
  -falign-loops=1 \
  -fno-ident \
  -fomit-frame-pointer \
  -nostdlib \
  -Wl,-e,mainCRTStartup \
  -Wl,--subsystem,windows \
  -Wl,--gc-sections

if [ "${TETRIS_SMOKE:-0}" = "1" ]; then
  set -- "$@" -DTETRIS_SMOKE=1
fi

zig cc \
  "$@" \
  -lkernel32 \
  -luser32 \
  -ld3d11 \
  -ldxgi \
  -lxaudio2_9 \
  -o "$output" \
  "$script_dir/tetris.c"
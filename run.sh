#!/bin/bash
set -ue

QEMU=qemu-system-riscv32
OBJCOPY=${OBJCOPY:-llvm-objcopy}

# Path to clang and compiler flags
# Allow override: CC=<path-to-clang> ./run.sh
CC=${CC:-clang}
CFLAGS="-std=c11 -O2 -g3 -Wall -Wextra --target=riscv32-unknown-elf -fuse-ld=lld -fno-stack-protector -ffreestanding -nostdlib"

# Build the shell (application)
$CC $CFLAGS -Wl,-Tuser.ld -Wl,-Map=shell.map -o shell.elf shell.c user.c common.c
$OBJCOPY --set-section-flags .bss=alloc,contents -O binary shell.elf shell.bin
$OBJCOPY -Ibinary -Oelf32-littleriscv shell.bin shell.bin.o

# Build the kernel
$CC $CFLAGS -Wl,-Tkernel.ld -Wl,-Map=kernel.map -o kernel.elf \
      boot.S kernel.c common.c shell.bin.o

# Create test files for tar archive
mkdir -p fs_contents
echo "Hello from the tar file system!" > fs_contents/hello.txt
echo "This is a test file." > fs_contents/test.txt
echo "This is another file for testing." > fs_contents/another.txt

# Create tar archive and write to disk image
echo "Creating tar archive..."
(cd fs_contents && tar cf ../disk.img --format=ustar *)
echo "Tar archive created successfully"

# Start QEMU
$QEMU -machine virt -bios default -nographic -serial mon:stdio --no-reboot \
    -kernel kernel.elf \
    -drive id=drive0,if=none,file=disk.img,format=raw \
    -device virtio-blk-device,drive=drive0

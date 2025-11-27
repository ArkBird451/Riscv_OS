# RISC-V Operating System

A minimal educational operating system for RISC-V (RV32) architecture running on QEMU, implementing core OS concepts in under 1000 lines of code.

## Features

- **Process Management**: Context switching, user/kernel mode separation
- **Memory Management**: Paging (SV32), virtual memory
- **System Calls**: putchar, readfile, listdir
- **Device Drivers**: 
  - virtio-blk (virtual disk)
  - UART console via SBI
- **File System**: TAR-based file system on virtio-blk
- **User Space**: Shell application demonstrating system calls

## Building and Running

### Prerequisites
- `clang` with RISC-V target support
- `qemu-system-riscv32`
- `llvm-objcopy`
- `tar`

### Build & Run
```bash
./run.sh
```

This will:
1. Compile the kernel and user applications
2. Create a tar archive with test files
3. Launch QEMU with the kernel and virtual disk

### Expected Output
```
virtio-blk: capacity is 10240 bytes
virtio-blk: initialized successfully
Initializing tar file system...

=== TAR File System Demonstration ===

1. Listing all files in archive:
Files in tar archive:
  another.txt (34 bytes)
  hello.txt (32 bytes)
  test.txt (21 bytes)

2. Reading 'hello.txt':
   Content: Hello from the tar file system!
```

## System Architecture

The OS is structured in three main layers:

**User Space**
- Shell application (shell.c) - Demonstrates file system operations
- User library (user.c) - System call wrappers and startup code
- Communicates with kernel via system calls (ecall instruction)

**Kernel Space**
- Process scheduler - Round-robin scheduling with context switching
- System call handler - Handles ecall traps from user space
- Memory management - SV32 paging with page tables for virtual memory
- TAR file system - Parses and reads USTAR format archives
- virtio-blk driver - Block device I/O using virtqueue interface
- Trap handler - Manages exceptions and interrupts

**Hardware Layer (QEMU)**
- RISC-V CPU (RV32IMAC) - Executes instructions in supervisor/user modes
- virtio-blk device - Virtual disk for persistent storage
- UART console - Character I/O via SBI (Supervisor Binary Interface)

## System Calls

The OS provides three system calls accessible from user space:

- **putchar (1)** - Write a single character to the console output
- **readfile (2)** - Read a file from the tar archive into a buffer (args: filename, buffer, size)
- **listdir (3)** - List all files in the tar archive with their sizes

## File System

The OS uses a TAR-based file system stored on a virtio-blk device:
- USTAR format support
- Read-only operations
- Sector-based I/O (512 bytes)
- Supports multiple files in a single archive

To modify files in the archive, edit `run.sh`:
```bash
# Add your files to fs_contents/
mkdir -p fs_contents
echo "Your content" > fs_contents/myfile.txt
```

## Project Structure

```
.
├── kernel.c       # Kernel implementation
├── kernel.h       # Kernel structures and definitions
├── kernel.ld      # Kernel linker script
├── boot.S         # Boot assembly code
├── common.c       # Common utilities (printf, memcpy, etc.)
├── common.h       # Common definitions
├── user.c         # User space startup and syscall wrappers
├── user.h         # User space definitions
├── user.ld        # User application linker script
├── shell.c        # Shell application
└── run.sh         # Build and run script
```

## Key Concepts Demonstrated

1. **Privilege Modes**: Supervisor (kernel) and User modes
2. **Virtual Memory**: SV32 paging with page tables
3. **Context Switching**: Between kernel and user space
4. **Trap Handling**: System calls and exceptions
5. **Device I/O**: MMIO-based virtio device driver
6. **File System**: Parsing and reading TAR archives
7. **Process Scheduling**: Simple round-robin scheduler

## Technical Details

- **Architecture**: RISC-V 32-bit (RV32IMAC)
- **Page Size**: 4KB
- **User Base Address**: 0x01000000
- **Kernel Base Address**: 0x80200000
- **virtio-blk MMIO**: 0x10008000
- **Sector Size**: 512 bytes

## References

Based on the "Operating System in 1,000 Lines" project by Seiya Nuta.

## License

Educational use only.


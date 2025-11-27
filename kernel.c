#include "kernel.h"
#include "common.h"

extern char __bss[], __bss_end[], __stack_top[];

struct sbiret sbi_call(long arg0, long arg1, long arg2, long arg3, long arg4,
                       long arg5, long fid, long eid) {
    register long a0 __asm__("a0") = arg0;
    register long a1 __asm__("a1") = arg1;
    register long a2 __asm__("a2") = arg2;
    register long a3 __asm__("a3") = arg3;
    register long a4 __asm__("a4") = arg4;
    register long a5 __asm__("a5") = arg5;
    register long a6 __asm__("a6") = fid;
    register long a7 __asm__("a7") = eid;

    __asm__ __volatile__("ecall"
                         : "=r"(a0), "=r"(a1)
                         : "r"(a0), "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a5),
                           "r"(a6), "r"(a7)
                         : "memory");
    return (struct sbiret){.error = a0, .value = a1};
}
__attribute__((naked))
__attribute__((aligned(4)))
void kernel_entry(void) {
    __asm__ __volatile__(
        "csrw sscratch, sp\n"
        "addi sp, sp, -4 * 31\n"
        "sw ra,  4 * 0(sp)\n"
        "sw gp,  4 * 1(sp)\n"
        "sw tp,  4 * 2(sp)\n"
        "sw t0,  4 * 3(sp)\n"
        "sw t1,  4 * 4(sp)\n"
        "sw t2,  4 * 5(sp)\n"
        "sw t3,  4 * 6(sp)\n"
        "sw t4,  4 * 7(sp)\n"
        "sw t5,  4 * 8(sp)\n"
        "sw t6,  4 * 9(sp)\n"
        "sw a0,  4 * 10(sp)\n"
        "sw a1,  4 * 11(sp)\n"
        "sw a2,  4 * 12(sp)\n"
        "sw a3,  4 * 13(sp)\n"
        "sw a4,  4 * 14(sp)\n"
        "sw a5,  4 * 15(sp)\n"
        "sw a6,  4 * 16(sp)\n"
        "sw a7,  4 * 17(sp)\n"
        "sw s0,  4 * 18(sp)\n"
        "sw s1,  4 * 19(sp)\n"
        "sw s2,  4 * 20(sp)\n"
        "sw s3,  4 * 21(sp)\n"
        "sw s4,  4 * 22(sp)\n"
        "sw s5,  4 * 23(sp)\n"
        "sw s6,  4 * 24(sp)\n"
        "sw s7,  4 * 25(sp)\n"
        "sw s8,  4 * 26(sp)\n"
        "sw s9,  4 * 27(sp)\n"
        "sw s10, 4 * 28(sp)\n"
        "sw s11, 4 * 29(sp)\n"

        //Retreive and save the sp at the time of exception.
        "csrr a0, sscratch\n"
        "sw a0, 4 * 30(sp)\n"

        // Reset the kernel stack.
        "addi a0, sp, 4 * 31\n"
        "csrw sscratch, a0\n"

        "mv a0, sp\n"
        "call handle_trap\n"

        "lw ra,  4 * 0(sp)\n"
        "lw gp,  4 * 1(sp)\n"
        "lw tp,  4 * 2(sp)\n"
        "lw t0,  4 * 3(sp)\n"
        "lw t1,  4 * 4(sp)\n"
        "lw t2,  4 * 5(sp)\n"
        "lw t3,  4 * 6(sp)\n"
        "lw t4,  4 * 7(sp)\n"
        "lw t5,  4 * 8(sp)\n"
        "lw t6,  4 * 9(sp)\n"
        "lw a0,  4 * 10(sp)\n"
        "lw a1,  4 * 11(sp)\n"
        "lw a2,  4 * 12(sp)\n"
        "lw a3,  4 * 13(sp)\n"
        "lw a4,  4 * 14(sp)\n"
        "lw a5,  4 * 15(sp)\n"
        "lw a6,  4 * 16(sp)\n"
        "lw a7,  4 * 17(sp)\n"
        "lw s0,  4 * 18(sp)\n"
        "lw s1,  4 * 19(sp)\n"
        "lw s2,  4 * 20(sp)\n"
        "lw s3,  4 * 21(sp)\n"
        "lw s4,  4 * 22(sp)\n"
        "lw s5,  4 * 23(sp)\n"
        "lw s6,  4 * 24(sp)\n"
        "lw s7,  4 * 25(sp)\n"
        "lw s8,  4 * 26(sp)\n"
        "lw s9,  4 * 27(sp)\n"
        "lw s10, 4 * 28(sp)\n"
        "lw s11, 4 * 29(sp)\n"
        "lw sp,  4 * 30(sp)\n"
        "sret\n"
    );
}

__attribute__((naked)) void switch_context(uint32_t *prev_sp,
                                           uint32_t *next_sp) {
    __asm__ __volatile__(
        // Save callee-saved registers onto the current process's stack.
        "addi sp, sp, -13 * 4\n" // Allocate stack space for 13 4-byte registers
        "sw ra,  0  * 4(sp)\n"   // Save callee-saved registers only
        "sw s0,  1  * 4(sp)\n"
        "sw s1,  2  * 4(sp)\n"
        "sw s2,  3  * 4(sp)\n"
        "sw s3,  4  * 4(sp)\n"
        "sw s4,  5  * 4(sp)\n"
        "sw s5,  6  * 4(sp)\n"
        "sw s6,  7  * 4(sp)\n"
        "sw s7,  8  * 4(sp)\n"
        "sw s8,  9  * 4(sp)\n"
        "sw s9,  10 * 4(sp)\n"
        "sw s10, 11 * 4(sp)\n"
        "sw s11, 12 * 4(sp)\n"

        // Switch the stack pointer.
        "sw sp, (a0)\n"         // *prev_sp = sp;
        "lw sp, (a1)\n"         // Switch stack pointer (sp) here

        // Restore callee-saved registers from the next process's stack.
        "lw ra,  0  * 4(sp)\n"  // Restore callee-saved registers only
        "lw s0,  1  * 4(sp)\n"
        "lw s1,  2  * 4(sp)\n"
        "lw s2,  3  * 4(sp)\n"
        "lw s3,  4  * 4(sp)\n"
        "lw s4,  5  * 4(sp)\n"
        "lw s5,  6  * 4(sp)\n"
        "lw s6,  7  * 4(sp)\n"
        "lw s7,  8  * 4(sp)\n"
        "lw s8,  9  * 4(sp)\n"
        "lw s9,  10 * 4(sp)\n"
        "lw s10, 11 * 4(sp)\n"
        "lw s11, 12 * 4(sp)\n"
        "addi sp, sp, 13 * 4\n"  // We've popped 13 4-byte registers from the stack
        "ret\n"
    );
}

void handle_trap(struct trap_frame *f) {
    uint32_t scause = READ_CSR(scause);
    uint32_t stval = READ_CSR(stval);
    uint32_t user_pc = READ_CSR(sepc);

    if ((scause & 0x1fff) == 8) { // Environment call from U-mode
        // System call from user mode
        switch (f->a7) {
            case SYS_PUTCHAR: // putchar
                sbi_call(f->a0, 0, 0, 0, 0, 0, 0, 1);
                break;
            
            case SYS_READFILE: { // readfile(filename, buf, size)
                const char *filename = (const char *)f->a0;
                char *buf = (char *)f->a1;
                int size = (int)f->a2;
                fs_read_file(filename, buf, size);
                break;
            }
            
            case SYS_LISTDIR: // listdir()
                fs_list_files();
                break;
            
            default:
                printf("Unknown syscall: %d\n", f->a7);
                break;
        }
        
        // Move past the ecall instruction (4 bytes)  
        user_pc += 4;
        WRITE_CSR(sepc, user_pc);
        return;
    }

    if ((scause & 0x1fff) == 2) { // illegal instruction
        PANIC("Illegal instruction at %x", user_pc);
    }

    if ((scause & 0x1fff) == 12) { // Instruction page fault
        PANIC("Instruction page fault at %x, addr=%x", user_pc, stval);
    }

    if ((scause & 0x1fff) == 13) { // Load page fault
        PANIC("Load page fault at %x, addr=%x", user_pc, stval);
    }

    if ((scause & 0x1fff) == 15) { // Store/AMO page fault
        PANIC("Store page fault at %x, addr=%x", user_pc, stval);
    }

    PANIC("unexpected trap scause=%x, stval=%x, sepc=%x", scause, stval, user_pc);
}

void putchar(char ch) {
    sbi_call(ch, 0, 0, 0, 0, 0, 0, 1 /* Console Putchar */);
}

extern char __free_ram[], __free_ram_end[];

static paddr_t next_paddr = 0;

paddr_t alloc_pages_get_allocated_end(void) {
    return next_paddr;
}

paddr_t alloc_pages(uint32_t n) {
    if (next_paddr == 0)
        next_paddr = (paddr_t) __free_ram;
        
    paddr_t paddr = next_paddr;
    next_paddr += n * PAGE_SIZE;

    if (next_paddr > (paddr_t) __free_ram_end)
        PANIC("out of memory");

    memset((void *) paddr, 0, n * PAGE_SIZE);
    return paddr;
}

extern char _binary_shell_bin_start[], _binary_shell_bin_size[];

struct process procs[PROCS_MAX];

extern char __kernel_base[];

void map_page(uint32_t *table1, uint32_t vaddr, paddr_t paddr, uint32_t flags);

void user_entry(void) {
    // Set SPIE (enable interrupts) and clear SPP (return to user mode)
    uint32_t sstatus = READ_CSR(sstatus);
    sstatus |= SSTATUS_SPIE;   // Enable interrupts in user mode
    sstatus &= ~SSTATUS_SPP;   // Clear SPP to return to user mode (U-mode)
    
    __asm__ __volatile__(
        "csrw sepc, %[sepc]\n"
        "csrw sstatus, %[sstatus]\n"
        "sret\n"
        :
        : [sepc] "r" (USER_BASE),
          [sstatus] "r" (sstatus)
    );
    
    __builtin_unreachable();
}

struct process *create_process(uint32_t pc) {
    // Map kernel pages (identity mapping: VA = PA)
    uint32_t *page_table = (uint32_t *) alloc_pages(1);
    
    // Map kernel code/data region
    for (paddr_t paddr = (paddr_t) __kernel_base;
         paddr < (paddr_t) __free_ram; paddr += PAGE_SIZE) {
        map_page(page_table, paddr, paddr, PAGE_R | PAGE_W | PAGE_X);
    }
    
    // Map allocated portion of free RAM (with some buffer for safety)
    paddr_t alloc_end = alloc_pages_get_allocated_end();
    paddr_t map_end = alloc_end + 4 * 1024 * 1024;
    if (map_end > (paddr_t) __free_ram_end)
        map_end = (paddr_t) __free_ram_end;
    
    for (paddr_t paddr = (paddr_t) __free_ram;
         paddr < map_end; paddr += PAGE_SIZE) {
        map_page(page_table, paddr, paddr, PAGE_R | PAGE_W | PAGE_X);
    }

    // Find an unused process slot
    struct process *proc = NULL;
    int i;
    for (i = 0; i < PROCS_MAX; i++) {
        if (procs[i].state == PROC_UNUSED) {
            proc = &procs[i];
            break;
        }
    }

    if (!proc)
        PANIC("no free process slots");

    // Initialize the process stack
    uint32_t *sp = (uint32_t *) &proc->stack[sizeof(proc->stack)];
    *--sp = 0;                      // s11
    *--sp = 0;                      // s10
    *--sp = 0;                      // s9
    *--sp = 0;                      // s8
    *--sp = 0;                      // s7
    *--sp = 0;                      // s6
    *--sp = 0;                      // s5
    *--sp = 0;                      // s4
    *--sp = 0;                      // s3
    *--sp = 0;                      // s2
    *--sp = 0;                      // s1
    *--sp = 0;                      // s0
    *--sp = (uint32_t) pc;          // ra

    proc->pid = i + 1;
    proc->state = PROC_RUNNABLE;
    proc->sp = (uint32_t) sp;
    proc->page_table = page_table;
    return proc;
}

struct process *create_process_from_elf(const void *image, size_t image_size) {
    // Map kernel pages (identity mapping: VA = PA)
    uint32_t *page_table = (uint32_t *) alloc_pages(1);
    
    // Map kernel code/data region
    for (paddr_t paddr = (paddr_t) __kernel_base;
         paddr < (paddr_t) __free_ram; paddr += PAGE_SIZE) {
        map_page(page_table, paddr, paddr, PAGE_R | PAGE_W | PAGE_X);
    }
    
    // Map virtio MMIO region for device access during syscalls
    for (paddr_t paddr = 0x10000000; paddr < 0x10010000; paddr += PAGE_SIZE) {
        map_page(page_table, paddr, paddr, PAGE_R | PAGE_W);
    }

    // Map user pages.
    for (uint32_t off = 0; off < image_size; off += PAGE_SIZE) {
        paddr_t page = alloc_pages(1);

        // Handle the case where the data to be copied is smaller than the
        // page size.
        size_t remaining = image_size - off;
        size_t copy_size = PAGE_SIZE <= remaining ? PAGE_SIZE : remaining;

        // Fill and map the page.
        memcpy((void *) page, image + off, copy_size);
        map_page(page_table, USER_BASE + off, page,
                 PAGE_U | PAGE_R | PAGE_W | PAGE_X);
    }
    
    // Map allocated portion of free RAM (with some buffer for safety)
    paddr_t alloc_end = alloc_pages_get_allocated_end();
    paddr_t map_end = alloc_end + 4 * 1024 * 1024;
    if (map_end > (paddr_t) __free_ram_end)
        map_end = (paddr_t) __free_ram_end;
    
    for (paddr_t paddr = (paddr_t) __free_ram;
         paddr < map_end; paddr += PAGE_SIZE) {
        map_page(page_table, paddr, paddr, PAGE_R | PAGE_W | PAGE_X);
    }

    // Find an unused process slot
    struct process *proc = NULL;
    int i;
    for (i = 0; i < PROCS_MAX; i++) {
        if (procs[i].state == PROC_UNUSED) {
            proc = &procs[i];
            break;
        }
    }

    if (!proc)
        PANIC("no free process slots");

    // Initialize the process stack
    uint32_t *sp = (uint32_t *) &proc->stack[sizeof(proc->stack)];
    *--sp = 0;                      // s11
    *--sp = 0;                      // s10
    *--sp = 0;                      // s9
    *--sp = 0;                      // s8
    *--sp = 0;                      // s7
    *--sp = 0;                      // s6
    *--sp = 0;                      // s5
    *--sp = 0;                      // s4
    *--sp = 0;                      // s3
    *--sp = 0;                      // s2
    *--sp = 0;                      // s1
    *--sp = 0;                      // s0
    *--sp = (uint32_t) user_entry;  // ra

    proc->pid = i + 1;
    proc->state = PROC_RUNNABLE;
    proc->sp = (uint32_t) sp;
    proc->page_table = page_table;
    return proc;
}

void delay(void) {
    for (int i = 0; i < 30000000; i++)
        __asm__ __volatile__("nop"); // do nothing
}

struct process *proc_a;
struct process *proc_b;

void yield(void);

void proc_a_entry(void) {
    printf("starting process A\n");
    while (1) {
        putchar('A');
        yield();
    }
}

void proc_b_entry(void) {
    printf("starting process B\n");
    while (1) {
        putchar('B');
        yield();
    }
}

void idle_entry(void) {
    while (1) {
        yield();
    }
}

struct process *current_proc;
struct process *idle_proc;

void yield(void) {
    struct process *next = idle_proc;
    for (int i = 0; i < PROCS_MAX; i++) {
         struct process *proc = &procs[(current_proc->pid + i) % PROCS_MAX];
         if (proc->state == PROC_RUNNABLE && proc->pid > 0) {
            next = proc;
            break;
         }
    }
    if (next == current_proc)
        return;

    __asm__ __volatile__(
        "sfence.vma\n"
        "csrw satp, %[satp]\n"
        "sfence.vma\n"
        "csrw sscratch, %[sscratch]\n"
        :
        : [satp] "r" (SATP_SV32 | ((uint32_t) next->page_table / PAGE_SIZE)),
          [sscratch] "r" ((uint32_t) &next->stack[sizeof(next->stack)])
    );

    struct process *prev = current_proc;
    current_proc = next;
    switch_context(&prev->sp, &next->sp);
}

void map_page(uint32_t *table1, uint32_t vaddr, paddr_t paddr, uint32_t flags) {
    if (!is_aligned(vaddr, PAGE_SIZE))
        PANIC("unaligned vaddr %x", vaddr);

    if (!is_aligned(paddr, PAGE_SIZE))
        PANIC("unaligned paddr %x", paddr);

    uint32_t vpn1 = (vaddr >> 22) & 0x3ff;
    if ((table1[vpn1] & PAGE_V) == 0) {
        uint32_t pt_paddr = alloc_pages(1);
        table1[vpn1] = ((pt_paddr / PAGE_SIZE) << 10) | PAGE_V;
    }

    uint32_t vpn0 = (vaddr >> 12) & 0x3ff;
    uint32_t *table0 = (uint32_t *) ((table1[vpn1] >> 10) * PAGE_SIZE);
    table0[vpn0] = ((paddr / PAGE_SIZE) << 10) | flags | PAGE_V;
}

extern char _binary_shell_bin_start[];
extern char _binary_shell_bin_size[];

// Forward declarations
void read_write_disk(void *buf, unsigned sector, int is_write);

// Tar file system implementation
static char disk_buf[SECTOR_SIZE];

// Convert octal string to integer (used for tar header fields)
static unsigned oct2int(const char *oct, int len) {
    unsigned value = 0;
    for (int i = 0; i < len && oct[i] >= '0' && oct[i] <= '7'; i++) {
        value = value * 8 + (oct[i] - '0');
    }
    return value;
}

// Initialize tar file system
void fs_init(void) {
    printf("Initializing tar file system...\n");
}

// List all files in the tar archive
void fs_list_files(void) {
    printf("Files in tar archive:\n");
    
    unsigned sector = 0;
    for (;;) {
        // Read sector
        read_write_disk(disk_buf, sector, 0);
        struct tar_header *header = (struct tar_header *) disk_buf;
        
        // Check if end of archive (empty block)
        if (header->name[0] == '\0') {
            break;
        }
        
        // Parse file size
        unsigned file_size = oct2int(header->size, sizeof(header->size));
        
        // Print file info
        printf("  %s (%d bytes)\n", header->name, file_size);
        
        // Move to next file (header + data blocks, rounded up to 512 bytes)
        unsigned data_sectors = (file_size + SECTOR_SIZE - 1) / SECTOR_SIZE;
        sector += 1 + data_sectors;
    }
}

// Find a file in the tar archive
struct tar_header *fs_lookup(const char *filename) {
    static char lookup_buf[SECTOR_SIZE];
    
    unsigned sector = 0;
    for (;;) {
        // Read sector
        read_write_disk(lookup_buf, sector, 0);
        struct tar_header *header = (struct tar_header *) lookup_buf;
        
        // Check if end of archive
        if (header->name[0] == '\0') {
            return NULL;
        }
        
        // Check if filename matches
        if (strcmp(header->name, filename) == 0) {
            return header;
        }
        
        // Move to next file
        unsigned file_size = oct2int(header->size, sizeof(header->size));
        unsigned data_sectors = (file_size + SECTOR_SIZE - 1) / SECTOR_SIZE;
        sector += 1 + data_sectors;
    }
}

// Read a file from the tar archive
void fs_read_file(const char *filename, char *buf, int size) {
    // Find file
    struct tar_header *header = fs_lookup(filename);
    if (!header) {
        printf("File not found: %s\n", filename);
        return;
    }
    
    // Get file size
    unsigned file_size = oct2int(header->size, sizeof(header->size));
    if (file_size > (unsigned)size) {
        printf("Buffer too small for file: %s\n", filename);
        return;
    }
    
    // Find the sector where this file's data starts
    // We need to search again to get the correct sector number
    unsigned sector = 0;
    for (;;) {
        read_write_disk(disk_buf, sector, 0);
        struct tar_header *h = (struct tar_header *) disk_buf;
        
        if (h->name[0] == '\0') {
            break;
        }
        
        if (strcmp(h->name, filename) == 0) {
            // Found it! Data starts at next sector
            sector++;
            break;
        }
        
        unsigned fs = oct2int(h->size, sizeof(h->size));
        unsigned data_sectors = (fs + SECTOR_SIZE - 1) / SECTOR_SIZE;
        sector += 1 + data_sectors;
    }
    
    // Read file data
    unsigned bytes_read = 0;
    while (bytes_read < file_size) {
        read_write_disk(disk_buf, sector, 0);
        
        unsigned bytes_to_copy = file_size - bytes_read;
        if (bytes_to_copy > SECTOR_SIZE) {
            bytes_to_copy = SECTOR_SIZE;
        }
        
        memcpy(buf + bytes_read, disk_buf, bytes_to_copy);
        bytes_read += bytes_to_copy;
        sector++;
    }
    
    // Null terminate if space available
    if (bytes_read < (unsigned)size) {
        buf[bytes_read] = '\0';
    }
}

// Global virtio-blk state pointers
struct virtio_virtq *blk_request_vq;
struct virtio_blk_req *blk_req;
paddr_t blk_req_paddr;

// Store capacity in a location that won't be overwritten
struct {
    unsigned capacity;
} blk_state;

// Helper functions to read/write virtio MMIO registers
static uint32_t virtio_reg_read32(unsigned offset) {
    return *((volatile uint32_t *) (VIRTIO_BLK_PADDR + offset));
}

static uint64_t virtio_reg_read64(unsigned offset) {
    return *((volatile uint64_t *) (VIRTIO_BLK_PADDR + offset));
}

static void virtio_reg_write32(unsigned offset, uint32_t value) {
    *((volatile uint32_t *) (VIRTIO_BLK_PADDR + offset)) = value;
}

static void virtio_reg_fetch_and_or32(unsigned offset, uint32_t value) {
    virtio_reg_write32(offset, virtio_reg_read32(offset) | value);
}

// Initialize virtio-blk device
struct virtio_virtq *virtq_init(unsigned index) {
    paddr_t virtq_paddr = alloc_pages(align_up(sizeof(struct virtio_virtq), PAGE_SIZE) / PAGE_SIZE);
    struct virtio_virtq *vq = (struct virtio_virtq *) virtq_paddr;
    vq->queue_index = index;
    vq->used_index = (volatile uint16_t *) &vq->used.index;
    
    // Select the queue
    virtio_reg_write32(VIRTIO_REG_QUEUE_SEL, index);
    
    // Check if queue is available
    if (virtio_reg_read32(VIRTIO_REG_QUEUE_NUM_MAX) == 0) {
        PANIC("virtqueue #%d does not exist", index);
    }
    
    // Set queue size
    virtio_reg_write32(VIRTIO_REG_QUEUE_NUM, VIRTQ_ENTRY_NUM);
    
    // Set queue address (page-aligned physical address)
    virtio_reg_write32(VIRTIO_REG_QUEUE_ALIGN, 0);
    virtio_reg_write32(VIRTIO_REG_QUEUE_PFN, virtq_paddr);
    
    return vq;
}

// Add a descriptor to the virtqueue
void virtq_kick(struct virtio_virtq *vq, int desc_index) {
    // Add to available ring
    vq->avail.ring[vq->avail.index % VIRTQ_ENTRY_NUM] = desc_index;
    vq->avail.index++;
    
    // Memory barrier
    __asm__ __volatile__("fence rw, rw" ::: "memory");
    
    // Notify device
    virtio_reg_write32(VIRTIO_REG_QUEUE_NOTIFY, vq->queue_index);
    
    // Wait for completion
    while (vq->last_used_index == *vq->used_index) {
        // Busy wait
    }
    
    vq->last_used_index++;
}

// Initialize virtio-blk driver
void virtio_blk_init(void) {
    // Check magic value
    if (virtio_reg_read32(VIRTIO_REG_MAGIC) != 0x74726976) {
        PANIC("virtio: invalid magic value");
    }
    
    // Check device version
    if (virtio_reg_read32(VIRTIO_REG_VERSION) != 1) {
        PANIC("virtio: unsupported version");
    }
    
    // Check device ID (should be 2 for block device)
    if (virtio_reg_read32(VIRTIO_REG_DEVICE_ID) != VIRTIO_DEVICE_BLK) {
        PANIC("virtio: not a block device");
    }
    
    // Reset device
    virtio_reg_write32(VIRTIO_REG_DEVICE_STATUS, 0);
    
    // Acknowledge device
    virtio_reg_fetch_and_or32(VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_ACK);
    
    // Set DRIVER status
    virtio_reg_fetch_and_or32(VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_DRIVER);
    
    // Read device capacity and store in struct
    blk_state.capacity = virtio_reg_read64(VIRTIO_REG_DEVICE_CONFIG + 0) * SECTOR_SIZE;
    printf("virtio-blk: capacity is %d bytes\n", blk_state.capacity);
    
    // Initialize request virtqueue
    blk_request_vq = virtq_init(0);
    
    // Set FEATURES_OK
    virtio_reg_fetch_and_or32(VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_FEAT_OK);
    
    // Set DRIVER_OK
    virtio_reg_fetch_and_or32(VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_DRIVER_OK);
    
    // Allocate request buffer
    blk_req_paddr = alloc_pages(align_up(sizeof(*blk_req), PAGE_SIZE) / PAGE_SIZE);
    blk_req = (struct virtio_blk_req *) blk_req_paddr;
    
    printf("virtio-blk: initialized successfully\n");
}

// Read a sector from the block device
void read_write_disk(void *buf, unsigned sector, int is_write) {
    if (sector >= blk_state.capacity / SECTOR_SIZE) {
        printf("virtio: tried to read/write sector=%d, but capacity is %d\n",
               sector, blk_state.capacity / SECTOR_SIZE);
        return;
    }
    
    // Setup request header
    blk_req->sector = sector;
    blk_req->type = is_write ? VIRTIO_BLK_T_OUT : VIRTIO_BLK_T_IN;
    
    // Copy data if writing
    if (is_write) {
        memcpy(blk_req->data, buf, SECTOR_SIZE);
    }
    
    // Setup descriptors
    // Descriptor 0: request header
    blk_request_vq->descs[0].addr = blk_req_paddr;
    blk_request_vq->descs[0].len = sizeof(uint32_t) * 2 + sizeof(uint64_t);
    blk_request_vq->descs[0].flags = VIRTQ_DESC_F_NEXT;
    blk_request_vq->descs[0].next = 1;
    
    // Descriptor 1: data buffer
    blk_request_vq->descs[1].addr = blk_req_paddr + offsetof(struct virtio_blk_req, data);
    blk_request_vq->descs[1].len = SECTOR_SIZE;
    blk_request_vq->descs[1].flags = VIRTQ_DESC_F_NEXT | (is_write ? 0 : VIRTQ_DESC_F_WRITE);
    blk_request_vq->descs[1].next = 2;
    
    // Descriptor 2: status byte
    blk_request_vq->descs[2].addr = blk_req_paddr + offsetof(struct virtio_blk_req, status);
    blk_request_vq->descs[2].len = sizeof(uint8_t);
    blk_request_vq->descs[2].flags = VIRTQ_DESC_F_WRITE;
    blk_request_vq->descs[2].next = 0;
    
    // Kick the queue
    virtq_kick(blk_request_vq, 0);
    
    // Check status
    if (blk_req->status != 0) {
        printf("virtio: warn: failed to read/write sector=%d status=%d\n",
               sector, blk_req->status);
        return;
    }
    
    // Copy data if reading
    if (!is_write) {
        memcpy(buf, blk_req->data, SECTOR_SIZE);
    }
}

void kernel_main(void) {
    memset(__bss, 0, (size_t) __bss_end - (size_t) __bss);

    printf("\n\n");

    WRITE_CSR(stvec, (uint32_t) kernel_entry);
    WRITE_CSR(sscratch, (uint32_t) __stack_top);

    // Initialize virtio-blk driver
    virtio_blk_init();
    
    // Initialize tar file system
    fs_init();
    
    // Demonstrate tar file system functionality
    printf("\n=== TAR File System Demonstration ===\n");
    printf("\n1. Listing all files in archive:\n");
    fs_list_files();
    
    printf("\n2. Reading 'hello.txt':\n");
    char file_buf[512];
    memset(file_buf, 0, sizeof(file_buf));
    fs_read_file("hello.txt", file_buf, sizeof(file_buf));
    printf("   Content: %s\n", file_buf);
    
    printf("\n3. Reading 'test.txt':\n");
    memset(file_buf, 0, sizeof(file_buf));
    fs_read_file("test.txt", file_buf, sizeof(file_buf));
    printf("   Content: %s\n", file_buf);
    
    printf("\n4. Reading 'another.txt':\n");
    memset(file_buf, 0, sizeof(file_buf));
    fs_read_file("another.txt", file_buf, sizeof(file_buf));
    printf("   Content: %s\n", file_buf);
    
    printf("\n=== TAR File System Test Complete ===\n\n");

    idle_proc = create_process((uint32_t) idle_entry);
    idle_proc->pid = 0;
    current_proc = idle_proc;
    
    create_process_from_elf(_binary_shell_bin_start, (size_t) _binary_shell_bin_size);
    
    yield();
    PANIC("switched to idle process");
}
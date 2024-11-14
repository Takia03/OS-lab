#include <lib/elf.h>
#include <lib/debug.h>
#include <lib/gcc.h>
#include <lib/seg.h>
#include <lib/trap.h>
#include <lib/x86.h>

#include "import.h"

extern tf_t uctx_pool[NUM_IDS];
extern char STACK_LOC[NUM_IDS][PAGESIZE];


//  This function transitions a process from kernel mode to user mode, setting up its execution context.
void proc_start_user(void)
{
    unsigned int cur_pid = get_curid();             // Get the current process ID.
    tss_switch(cur_pid);                            // Switch the Task State Segment (TSS) to the current process.
    set_pdir_base(cur_pid);                         // Load the current process's page directory for memory management.
    trap_return((void *) &uctx_pool[cur_pid]);      // Restore the process's context and transfer control to user mode.
}


// This function creates a new process, loads its executable, and sets up its initial execution state.
unsigned int proc_create(void *elf_addr, unsigned int quota)
{
    unsigned int pid, id;

    id = get_curid();                                           // Get the current process ID.
    pid = thread_spawn((void *) proc_start_user, id, quota);    // Create a new thread that starts with `proc_start_user`.

    if (pid != NUM_IDS) {                                       // If a valid PID was returned:
        elf_load(elf_addr, pid);                                // Load the ELF binary into the process's memory.

        // Set up the process's initial user-mode segment registers.
        uctx_pool[pid].es = CPU_GDT_UDATA | 3;
        uctx_pool[pid].ds = CPU_GDT_UDATA | 3;
        uctx_pool[pid].cs = CPU_GDT_UCODE | 3;
        uctx_pool[pid].ss = CPU_GDT_UDATA | 3;

        // Set up the process's stack and execution state.
        uctx_pool[pid].esp = VM_USERHI;                         // User stack pointer (top of the user space).
        uctx_pool[pid].eflags = FL_IF;                          // Enable interrupts.
        uctx_pool[pid].eip = elf_entry(elf_addr);               // Entry point of the ELF binary.
    }

    return pid;                                                 // Return the new process's PID.
}


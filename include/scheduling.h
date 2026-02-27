#pragma once

#include <stdint.h>
#include "../MemoryManagement/include/cos_memory_api.h"

//https://www.felixcloutier.com/x86/fxsave
typedef struct fpu_state {
    uint64_t available[3][2];
    uint64_t reserved_2[3][2];
    uint64_t xmm[16][2];
    uint64_t st[8][2];
    uint32_t mxcsr_mask;
    uint32_t mxcsr;
    uint16_t reserved_1;
    uint16_t reserved_0;
    uint16_t fcs;
    uint32_t fip;
    uint16_t fop;
    uint16_t ftw;
    uint16_t fsw;
    uint16_t fcw;
    uint16_t fds;
    uint32_t fdp;
} __attribute__((packed)) fpu_state_t;

typedef struct {
    uint64_t rip;
    uint64_t cs;
    uint64_t flags;
    uint64_t rsp;
    uint64_t ss;
} __attribute__((packed)) iret_stack_frame_t;

typedef struct cos_cpu_state {
    //uint64_t cr4;
    uint64_t cr3;
    //uint64_t cr2;
    //uint64_t cr0;
    uint64_t gs;
    uint64_t fs;
    uint64_t rbp;
    uint64_t r15;
    uint64_t r14;
    uint64_t r13;
    uint64_t r12;
    uint64_t r11;
    uint64_t r10;
    uint64_t r9;
    uint64_t r8;
    uint64_t rax;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rsi;
    uint64_t rdi;
    //Due to initialisation of every process, these two values are always at least 0 anyway.
    uint64_t reserved_0;
    uint64_t reserved_1;
    iret_stack_frame_t stack_frame;
    uint8_t x87_state[512];
} __attribute__((packed)) cos_cpu_state_t;

typedef struct cos_process {
    uint64_t id;
    uint64_t privilege_level;
    uint64_t process_start;
    uint64_t quantum;
    page_frame_entry_t *allocated_page_reserved;
    page_frame_entry_t *allocated_process_memory;

    uint64_t stack_top;
    uint64_t kernel_stack_top;

    uint64_t heap_start;
    uint64_t heap_end;

    //This is an issue due to page limits being 4096 bytes.
    cos_cpu_state_t register_states;
    page_table_t *page_table;
    struct cos_process *next_proc;
    struct cos_process *prev_proc;
    char *command;
}  cos_process_t;

typedef struct cos_scheduling_properties {

    cos_process_t *process_list;
    cos_process_t *free_process_list;

    uint64_t number_of_processes;
    cos_process_t kernel_process;

} cos_scheduling_properties_t;

extern cos_scheduling_properties_t scheduling_properties;

page_table_t *kernel_make_process_page_table(cos_process_t * proc);
uint64_t map_process_section(uint64_t virt_addr, uint64_t size);
void init_scheduler(void);

extern void backup_cpu_state(cos_cpu_state_t *cpu_state, uint8_t *interprocess_buffer_copy_zone, uint64_t buffer_zone_size, uint8_t *stack_top);
extern void *windows_rearrange_arguments(void *function, uint64_t number_arguments);
cos_process_t *create_new_process(uint64_t privilege_level, const uint64_t user_stack, char *proc_command);

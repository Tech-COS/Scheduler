#include "scheduling.h"
#include "kernel/asm.h"
#include "kernel/cos_memory.h"
#include "kernel/idt.h"
#include "kernel/interrupts.h"
#include <stdint.h>
#include <stdnoreturn.h>
#include "kernel/term/tty.h"
#include "kernel/term/commands.h"
#include "kernel/lib/string.h"
#include "kernel/cos_time.h"

extern uint64_t handle_unix_timestamp(uint64_t new_timestamp);
extern void load_page_table(uint64_t page_table_pointer);

static void switch_process(cos_process_t *proc)
{
    scheduling_properties.process_list = proc;
    load_page_table((uint64_t)scheduling_properties.process_list->page_table);
}

void lock_cpu_state(void)
{
    __asm__ volatile("cli\t\n");
}

void unlock_cpu_state(void)
{
    __asm__ volatile("sti\t\n");
}

static cos_process_t *initialise_process(cos_process_t *new_proc, const uint64_t privilege_level, const uint64_t user_stack, char *proc_command)
{
    cos_process_t *temp_proc = scheduling_properties.process_list;
    uint64_t size = 16 * DEFAULT_BLOCK_SIZE;

    //Each process stacks have a fixed size of 64Kib.
    //UPDATE: PE format give the stack and heap sizes necessary for the program.
    //Dynamic growth could be considered.

    new_proc->page_table = kernel_make_process_page_table(new_proc);
    if (!new_proc->kernel_stack_top) {
        if (!(new_proc->kernel_stack_top = (uint64_t)cos_malloc(size)))
            return NULL;
        memset((void *)new_proc->kernel_stack_top, 0, size);
        new_proc->kernel_stack_top += size;
    }
    if (privilege_level) {
        new_proc->stack_top = PROCESS_STACK_TOP_ADDRESS;
        if (user_stack)
            size = user_stack;
        switch_process(new_proc);
        map_process_section(new_proc->stack_top - size, size);
        switch_process(temp_proc);
    } else
        new_proc->stack_top = new_proc->kernel_stack_top;

    new_proc->privilege_level = privilege_level;
    if (scheduling_properties.kernel_process.prev_proc)
        new_proc->id = scheduling_properties.kernel_process.prev_proc->id + 1;
    else
        new_proc->id = 1;
    new_proc->process_start = handle_unix_timestamp(0);
    new_proc->command = cos_malloc(sizeof(char) * cos_strlen(proc_command) + 1);
    memset(new_proc->command, 0, cos_strlen(proc_command) + 1);
    cos_memcpy(new_proc->command, proc_command, cos_strlen(proc_command));
    return new_proc;
}

cos_process_t *create_new_process(uint64_t privilege_level, const uint64_t user_stack, char *proc_command)
{
    cos_process_t *new_proc = NULL;

    //If several processes call this function, a race condition might occur and the same process can be selected several times if one of them is marked as free.
    //Otherwise, the process list could become corrupted and crash the kernel.

    if (scheduling_properties.free_process_list) {
        new_proc = scheduling_properties.free_process_list;

        scheduling_properties.free_process_list = new_proc->next_proc;
        if (scheduling_properties.kernel_process.prev_proc) {
            scheduling_properties.kernel_process.prev_proc->next_proc = new_proc;
            new_proc->prev_proc = scheduling_properties.kernel_process.prev_proc;
            scheduling_properties.kernel_process.prev_proc = new_proc;
        } else {
            scheduling_properties.kernel_process.next_proc = new_proc;
            scheduling_properties.kernel_process.prev_proc = new_proc;
            new_proc->prev_proc = &scheduling_properties.kernel_process;
        }
        new_proc->next_proc = &scheduling_properties.kernel_process;

        if (!initialise_process(new_proc, privilege_level, user_stack, proc_command)) {
            return NULL;
        }
        return new_proc;
    }

    if (!(new_proc = cos_malloc(sizeof(cos_process_t)))) {
        return NULL;
    }
    memset(new_proc, 0, sizeof(cos_process_t));

    if (!initialise_process(new_proc, privilege_level, user_stack,proc_command)) {
        cos_free(new_proc);
        return NULL;
    }

    if (!scheduling_properties.kernel_process.next_proc) {
        scheduling_properties.kernel_process.next_proc = new_proc;
        new_proc->prev_proc = &scheduling_properties.kernel_process;
    } else {
        scheduling_properties.kernel_process.prev_proc->next_proc = new_proc;
        new_proc->prev_proc = scheduling_properties.kernel_process.prev_proc;
    }

    new_proc->next_proc = &scheduling_properties.kernel_process;
    scheduling_properties.kernel_process.prev_proc = new_proc;
    ++scheduling_properties.number_of_processes;

    return new_proc;
}

static void reinit_process(cos_process_t *temp_proc)
{
    //Once allocated_page_reserved and allocated_process_memory are cleared of all their elements, the local heap blocks and the process stack are entirely freed.
    temp_proc->heap_start = 0;
    temp_proc->heap_end = 0;
    temp_proc->stack_top = 0;
    memset(&temp_proc->register_states, 0, sizeof(cos_cpu_state_t));
}

void destroy_process(cos_process_t *temp_proc)
{
    page_frame_entry_t *page_table_block = NULL;
    //If two or more processes are calling this function with the same argument, a race condition WILL occur and crash the kernel.
    //To patch this issue, the scheduler has to be put on hold and allow this function to continue until the process is marked as free.

    if (!temp_proc || !temp_proc->id)
        return;

    reinit_process(temp_proc);
    while (temp_proc->allocated_process_memory)
        temp_proc->allocated_process_memory = release_memory_blocks(temp_proc->page_table, temp_proc->allocated_process_memory);

    while (temp_proc->allocated_page_reserved) {
        if (temp_proc->allocated_page_reserved->virt_addr == (uint64_t)temp_proc->page_table) {
            page_table_block = temp_proc->allocated_page_reserved;
            temp_proc->allocated_page_reserved = temp_proc->allocated_page_reserved->next_frame;
            continue;
        }
        temp_proc->allocated_page_reserved = release_memory_blocks(temp_proc->page_table, temp_proc->allocated_page_reserved);
    }
    switch_process(&scheduling_properties.kernel_process);
	if (temp_proc->command)
		cos_free(temp_proc->command);
    release_page_table_block(page_table_block);

    temp_proc->prev_proc->next_proc = temp_proc->next_proc;
    temp_proc->next_proc->prev_proc = temp_proc->prev_proc;
    if (scheduling_properties.kernel_process.next_proc == &scheduling_properties.kernel_process) {
        scheduling_properties.kernel_process.next_proc = NULL;
        scheduling_properties.kernel_process.prev_proc = NULL;
    }

    temp_proc->prev_proc = NULL;
    temp_proc->next_proc = scheduling_properties.free_process_list;
    scheduling_properties.free_process_list = temp_proc;
    --scheduling_properties.number_of_processes;
}

//This is awful.
extern uint8_t x87_state[];
extern noreturn void _cos_exit(int64_t status, uint64_t kernel_stack);
extern void _cos_write(uint64_t file_desc, const char *str, size_t size);

//Microsoft x64 ABI
//https://learn.microsoft.com/en-us/cpp/build/x64-software-conventions?view=msvc-180

//Must be preserved: RDI, RSI, RBX, RSP, RBP, R12, R13, R14, R15, XMM6 - XMM15
//Direction flag is expected to be cleared on entry and exit.
//System V ABI preserves RBX, RSP, RBP, R12, R13, R14, R15 automatically.
//As such, rdi and rsi are preserved using the push instructions.
//TODO: XMM6 - XMM15 should be preserved as well.
//Since the System V ABI considers rdi, rsi, rdx and rcx as scratch registers and the Windows ABI considers rdx and rcx as scratch registers,
//every mov can be safely made without breaking the PE32+ binary upon return.
//As the kernel isn't optimised, rbp is always used by GCC to calculate the offset needed to access the temporary allocated variables and the function arguments.
//Also, rbp is always placed such that it points to its own saved state.
//As the return address is placed above followed by the remaining arguments in reverse order, the argument list starts at rbp + 16.
//Using the number of arguments, it becomes trivial to shift the arguments twice to the left
//and end in a System V ABI compliant stack, as the last two arguments in the list will never be used by the equivalent function.
//r10 and r11 being scratch registers on both platforms, they can be safely used to push the arguments in the correct order for the System V ABI.
//AT & T Syntax demystification for the expression: 24(%%rbp, %%r9, 8)
//rbp is the base.
//24 is the offset from the current address stored in the base.
//r9 is the index in the array starting at the current address stored in the base + its offset.
//8 is the index's multiplier.
//As the stack is made to work with x64 binary, the stack contains 8 byte sized values.
#define WINDOWS_ARGUMENTS_REARRANGE(function, number_arguments) \
    ({ \
    __asm__ __volatile__( \
            "cld\n" \
			"pop %%rdx\n" \
    		"push %%rdi\n" \
    		"push %%rsi\n" \
    		"mov %%rcx, %%rdi\n" \
    		"mov %%rdx, %%rsi\n" \
    		"mov %%r8, %%rdx\n" \
    		"mov %%r9, %%rcx\n" \
			"mov %[nb], %%r9\n" \
			"cmp $5, %%r9\n" \
			"jb 2f\n" \
			"je 1f\n" \
			"sub $6, %%r9\n" \
			"je 4f\n" \
		"3:\n" \
			"push 24(%%rbp, %%r9, 8)\n" \
			"dec %%r9\n" \
			"jne 3b\n" \
		"4:\n" \
			"mov 24(%%rbp), %%r9\n" \
		"1:\n" \
			"mov 16(%%rbp), %%r8\n" \
		"2:\n" \
			"call *%[input_func]\n" \
			"mov %[nb], %%r9\n" \
			"sub $6, %%r9\n" \
			"jbe 6f\n" \
		"5:\n" \
			"pop %%r8\n" \
			"dec %%r9\n" \
			"jne 5b\n" \
		"6:\n" \
			"pop %%rsi\n" \
			"pop %%rdi\n" \
			"cld\n" \
		: \
        : [input_func] "r"(function), [nb] "i"(number_arguments) \
		: "rdi", "rsi", "rdx", "rcx", "r9", "r8", "rax" \
    ); \
})

void cos_write(uint64_t file_desc, const char *data, size_t size)
{
	_cos_write(file_desc, data, size);
}

noreturn void cos_exit(int64_t status)
{
    _cos_exit(status, scheduling_properties.kernel_process.stack_top);
}

//uint32_t status
void fake_exitprocess(void)
{
	__asm__ __volatile__("push %%rdx\n" :::);
    WINDOWS_ARGUMENTS_REARRANGE(cos_exit, 0);
}

//void *handle, char *text, uint32_t size, uint32_t *ptr, void *ptr2
//How to handle arguments sent to stack?
void fake_cos_write(void)
{
	__asm__ __volatile__("push %%rdx\n" :::);
	WINDOWS_ARGUMENTS_REARRANGE(cos_write, 3);
}

//uint32_t handle
void *fake_getstdhandle(void)
{
    return NULL;
}

uint64_t get_function_bind_address(const char *function_name)
{
	if (!cos_strcmp(function_name, "exit"))
		return (uint64_t)cos_exit;
	if (!cos_strcmp(function_name, "write"))
		return (uint64_t)cos_write;
    if (!cos_strcmp(function_name, "ExitProcess"))
        return (uint64_t)fake_exitprocess;
    if (!cos_strcmp(function_name, "GetStdHandle"))
        return (uint64_t)fake_getstdhandle;
    if (!cos_strcmp(function_name, "WriteConsoleA"))
        return (uint64_t)fake_cos_write;
    return 0;
}

static void resolve_imports(const BinFileData_t *bin_file_data)
{
    if (!bin_file_data->imported_libraries)
        return;
    if (!bin_file_data->imported_libraries[0].required_functions)
    {
        for (uint64_t i = 0; bin_file_data->imported_libraries[i].name != NULL; ++i)
        {
            *(uint64_t *)bin_file_data->imported_libraries[i].first_thunk = get_function_bind_address(bin_file_data->imported_libraries[i].name);
        }
        return;
    }
    for (uint64_t i = 0; bin_file_data->imported_libraries[i].required_functions; ++i)
    {
        for (uint64_t j = 0; bin_file_data->imported_libraries[i].required_functions[j].hint_or_ordinal; ++j)
        {
            *(uint64_t *)(bin_file_data->imported_libraries[i].first_thunk + bin_file_data->bin_load_address + j * 8) = get_function_bind_address(bin_file_data->imported_libraries[i].required_functions[j].name);
        }
    }
}

//The few first instructions set up the stack frame.
//Once unlock_cpu_state is reached, interrupts will resume and the CPU will reach the scheduler.
//Once the process is switched, the interrupt handler will execute the interrupt return instruction, replacing the former stack frame which was empty as the process just started.
//By placing the entry_point address at the bottom of the stack (called stack_top in the code because it is its TOP ADDRESS in the virtual address space), the RIP pointer
//will be loaded with it, resuming code execution at the address provided.
//According to information found online, register states upon entry MOSTLY aren't the kernel's problem.
//ELF format using __libc_start will be waiting for an argc, argv and env pointers at the bottom of its stack and will set up register state itself.
//PE format is unclear due to NtCreateUserProcess being undocumented. Research into this already reversed function is pending.
//Eflags and CS registers CANNOT BE SET TO 0.
void launch_new_user_process(const BinFileData_t *bin_file_data, uint8_t *binary, char *proc_command)
{
    lock_cpu_state();
    uint64_t highest_segment_address = 0;
    cos_process_t *user_proc = create_new_process(3, bin_file_data->stack_size, proc_command);

    switch_process(user_proc);
    user_proc->register_states.rbp = user_proc->stack_top;
    user_proc->register_states.cr3 = (uint64_t)virtual_to_physical_address(user_proc->page_table, (uint64_t)user_proc->page_table);
    user_proc->register_states.stack_frame.cs = 0x20 | 3;
    user_proc->register_states.stack_frame.flags = 0x202;
    user_proc->register_states.stack_frame.rip = bin_file_data->entry_point;
    user_proc->register_states.stack_frame.rsp = user_proc->stack_top;
    user_proc->register_states.stack_frame.ss = 0x18 | 3;
    user_proc->register_states.gs = 0x18 | 3;
    user_proc->register_states.fs = 0x18 | 3;

    for (uint64_t i = 0; i < bin_file_data->number_of_sections; ++i)
    {
        if (!bin_file_data->sections[i].size)
            continue;
        map_process_section(bin_file_data->sections[i].address, bin_file_data->sections[i].size);
        cos_memcpy((void *)bin_file_data->sections[i].address, &binary[bin_file_data->sections[i].offset], bin_file_data->sections[i].size);
        if (highest_segment_address < bin_file_data->sections[i].size + bin_file_data->sections[i].address)
            highest_segment_address = bin_file_data->sections[i].size + bin_file_data->sections[i].address;
    }

    user_proc->heap_start = (highest_segment_address & ~0xFFF) + 0x2000;
    user_proc->heap_end = user_proc->heap_start + bin_file_data->heap_size;
    map_process_section(user_proc->heap_start, bin_file_data->heap_size);
    resolve_imports(bin_file_data);

    switch_process(&scheduling_properties.kernel_process);
    unlock_cpu_state();
}

uint64_t cos_fork(void)
{
    lock_cpu_state();
    cos_process_t *current_proc = scheduling_properties.process_list;
    cos_cpu_state_t cpu_status = {0};
    cos_process_t *proc = create_new_process(scheduling_properties.process_list->privilege_level, 0, scheduling_properties.process_list->command);

    if (!proc) {
        unlock_cpu_state();
        return -1;
    }
    for (uint64_t i = 0; i < 510; ++i)
        proc->page_table->entries[i] = scheduling_properties.process_list->page_table->entries[i];
    //Copy-on-write will be added to handle heap/.data accesses.
    //The idea is to allocate a new block to a process trying to write data into shared memory and then memcpy the content it
    //tried to modify into this new block.
    //When this is done, the new block is remapped to the same memory address, meaning the data is exactly in the "same place" as the parent and execution will
    //transparently continue.
    //This requires momentarily changing shared pages to read only mode which will trigger a page fault when a process try to change their content.
    //If all children have exited, the parent process can commit the changes to itself and the kernel can reclaim the unused memory from the copy-on-write mechanism.
    proc->heap_end = scheduling_properties.process_list->heap_end;
    proc->heap_start = scheduling_properties.process_list->heap_start;

    backup_cpu_state(&cpu_status, (uint8_t *)(proc->kernel_stack_top - 65536), 65536, (uint8_t *)(scheduling_properties.process_list->stack_top - 65536));

    //This works because the race is always won by the parent process.
    //Execution of the child continues from within backup_cpu_status to here.
    //Even if cpu_status isn't the same for both the parent and child (shouldn't happen as the same instructions are executed in both processes),
    //the variable is cleared from stack after cos_fork returns and won't matter anyway.
    //This isn't a good way to do things though.
    if (current_proc != scheduling_properties.process_list) {
        unlock_cpu_state();
        return 0;
    }

    proc->register_states = cpu_status;
    proc->register_states.stack_frame.rsp = proc->stack_top - (current_proc->stack_top - cpu_status.stack_frame.rsp);
    proc->register_states.rbp = proc->stack_top - (current_proc->stack_top - cpu_status.rbp);
    proc->register_states.cr3 = (uint64_t)virtual_to_physical_address(proc->page_table, (uint64_t)proc->page_table) | (cpu_status.cr3 & 0xFFF);

    if (proc->privilege_level) {
        switch_process(proc);
        cos_memcpy((void *)(proc->stack_top - 65536), (void *)(proc->kernel_stack_top - 65536), 16 * DEFAULT_BLOCK_SIZE);
        switch_process(current_proc);
    }

    unlock_cpu_state();
    return proc->id;
}

typedef struct task_segment {
    uint32_t reserved0;
    uint64_t rsp0;
    uint64_t rsp1;
    uint64_t rsp2;
    uint64_t reserved1;
    uint64_t ist1;
    uint64_t ist2;
    uint64_t ist3;
    uint64_t ist4;
    uint64_t ist5;
    uint64_t ist6;
    uint64_t ist7;
    uint64_t reserved2;
    uint16_t reserved3;
    uint16_t iopb;
} __attribute__((packed)) tss_t;

extern tss_t tss;

//This is basically the round-robin algorithm without priority handling.
void cos_scheduling_handler(cos_cpu_stack *stack)
{
    if (!scheduling_properties.process_list || !scheduling_properties.process_list->next_proc) {
        cos_outb(0x20, 0x20);
        return;
    }
    cos_memcpy(&scheduling_properties.process_list->register_states, stack, sizeof(*stack));
    cos_memcpy(scheduling_properties.process_list->register_states.x87_state, x87_state, 512);
    scheduling_properties.process_list = scheduling_properties.process_list->next_proc;
    cos_memcpy(stack, &scheduling_properties.process_list->register_states, sizeof(*stack));
    cos_memcpy(x87_state, scheduling_properties.process_list->register_states.x87_state, 512);
    cos_outb(0x20, 0x20);
}

void print_processes(void)
{
    uint64_t timestamp = handle_unix_timestamp(0);
    cos_process_t *proc = &scheduling_properties.kernel_process;
    datetime_t current_dt = {0};

    cos_printf("    PID TTY      TIME     CMD\n");
    do
    {
        unix_to_datetime(timestamp - proc->process_start, &current_dt);
        cos_printf("    %d", proc->id);
        cos_printf("   pts/0    ");
        if (current_dt.hour < 10)
        {
            cos_printf("0%d:", current_dt.hour);
        } else
        {
            cos_printf("%d:", current_dt.hour);
        }
        if (current_dt.minute < 10)
        {
            cos_printf("0%d:", current_dt.minute);
        } else
        {
            cos_printf("%d:", current_dt.minute);
        }
        if (current_dt.second < 10)
        {
            cos_printf("0%d ", current_dt.second);
        } else
        {
            cos_printf("%d ", current_dt.second);
        }
        cos_printf("%s\n", proc->command);
        proc = proc->next_proc;
    } while (proc && proc != scheduling_properties.process_list);
}

void cos_exit_handler(int64_t status, cos_cpu_stack **stack)
{
    cos_process_t *temp_proc = scheduling_properties.process_list;

    lock_cpu_state();
    (void)status;
    scheduling_properties.process_list = &scheduling_properties.kernel_process;
    destroy_process(temp_proc);

    scheduling_properties.process_list = &scheduling_properties.kernel_process;
    cos_memcpy(*stack, &scheduling_properties.process_list->register_states, sizeof(**stack));
    cos_memcpy(x87_state,scheduling_properties.process_list->register_states.x87_state, 512);
}

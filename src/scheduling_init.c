#include "scheduling.h"
#include <stdint.h>

extern void reload_tss(uint64_t stack_ptr);
extern void cos_memcpy(void *dest_buffer, void *source_buffer, unsigned long data_size);
extern uint64_t handle_unix_timestamp(uint64_t new_timestamp);

cos_scheduling_properties_t scheduling_properties;

void init_scheduler(void)
{
    extern unsigned long kernel_stack_top[];

    request_kernel_lists(&scheduling_properties.kernel_process.allocated_page_reserved, 
        &scheduling_properties.kernel_process.allocated_process_memory,
        &scheduling_properties.kernel_process.page_table);

    request_heap_addresses(&scheduling_properties.kernel_process.heap_start, 
        &scheduling_properties.kernel_process.heap_end);

    scheduling_properties.process_list = &scheduling_properties.kernel_process;
    scheduling_properties.number_of_processes = 1;
    scheduling_properties.kernel_process.stack_top = (uint64_t)kernel_stack_top;
    scheduling_properties.kernel_process.kernel_stack_top = (uint64_t)kernel_stack_top;
    scheduling_properties.kernel_process.privilege_level = 0;
    scheduling_properties.kernel_process.process_start = handle_unix_timestamp(0);

    scheduling_properties.kernel_process.command = cos_malloc(13);
    cos_memcpy(scheduling_properties.kernel_process.command, "kernel_start", 13);
    reload_tss(scheduling_properties.kernel_process.stack_top);
}

#include "scheduling.h"
#include <stdint.h>

extern void *memset(void *ptr, int character, size_t size);

void init_heap_object(malloc_heap_object_t *heap_object)
{
    heap_object->heap_start = scheduling_properties.process_list->heap_start;
    heap_object->heap_end = scheduling_properties.process_list->heap_end;
}

bool init_process_section(cos_process_t *proc, uint64_t heap_virt_addr)
{
    uint64_t level_4_index = (heap_virt_addr >> 39) & 0x1FF;
    uint64_t level_3_index = (heap_virt_addr >> 30) & 0x1FF;
    uint64_t level_2_index = (heap_virt_addr >> 21) & 0x1FF;
    uint64_t level_1_index = (heap_virt_addr >> 12) & 0x1FF;

    if (!proc || !proc->page_table)
        return false;

    if (!proc->page_table->entries[level_4_index]) {
        if (!allocate_memory_blocs(1, true, &proc->allocated_page_reserved, &proc->allocated_process_memory))
            return false;
        proc->page_table->entries[level_4_index] = proc->allocated_page_reserved->address | 0b111;
        proc->allocated_page_reserved->virt_addr = PML4_ENTRY(level_4_index);
        memset((void *)(PML4_ENTRY(level_4_index) & ~0xfff), 0, sizeof(page_table_t));
    }

    if (!((page_table_t *)(PML4_ENTRY(level_4_index)))->entries[level_3_index]) {
        if (!allocate_memory_blocs(1, true, &proc->allocated_page_reserved, &proc->allocated_process_memory))
            return false;
        ((page_table_t *)(PML4_ENTRY(level_4_index)))->entries[level_3_index] = proc->allocated_page_reserved->address | 0b111;
        proc->allocated_page_reserved->virt_addr = PUD_ENTRY(level_4_index, level_3_index);
        memset((void *)(PUD_ENTRY(level_4_index, level_3_index) & ~0xfff), 0, sizeof(page_table_t));
    }

    if (!((page_table_t *)(PUD_ENTRY(level_4_index, level_3_index)))->entries[level_2_index]) {
        if (!allocate_memory_blocs(1, true, &proc->allocated_page_reserved, &proc->allocated_process_memory))
            return false;
        ((page_table_t *)(PUD_ENTRY(level_4_index, level_3_index)))->entries[level_2_index] = proc->allocated_page_reserved->address | 0b111;
        proc->allocated_page_reserved->virt_addr = PMD_ENTRY(level_4_index, level_3_index, level_2_index);
        memset((void *)(PMD_ENTRY(level_4_index, level_3_index, level_2_index) & ~0xfff), 0, sizeof(page_table_t));
    }

    if (((page_table_t *)PMD_ENTRY(level_4_index, level_3_index, level_2_index))->entries[level_1_index]) {
        //cos_printf("ABORT: Heap cannot be initialised at address %X because data is already present in memory.", heap_virt_addr);
        return false;
    }

    if (!allocate_memory_blocs(1, true, &proc->allocated_page_reserved, &proc->allocated_process_memory))
        return false;
    ((page_table_t *)PMD_ENTRY(level_4_index, level_3_index, level_2_index))->entries[level_1_index] = proc->allocated_page_reserved->address | 0b111;
    proc->allocated_page_reserved->virt_addr = heap_virt_addr;
    return true;
}

//At this stage of the project, the heap is not located within the .data section of the program but at an address which shouldn't interfere with the program's execution (Read far into its virtual memory addressing.).
//As such, expansion shouldn't stop until several gigabytes or terabytes of heap have been requested.
//For legacy reasons of this memory architecture, the reserved pages of the kernel have to be moved in the allocated list.
//Also, it was arbitrarily chosen that every process heap would start at the beginning of a new page.
//TODO: Using the size requested, it should be possible to speed up this process significantly by allocating as many pages as necessary by precomputing the number of requested blocks before mapping them in RAM.
uint64_t expand_section(uint64_t next_heap_addr,  uint64_t size)
{
    uint64_t duplicated = 0;
    uint64_t consecutive_virt_addr_found = 0;
    uint64_t total_frames = 0;
    uint64_t start_virt_addr_level_4_index = (next_heap_addr >> 39) & 0x1FF;
    uint64_t start_virt_addr_level_3_index = (next_heap_addr >> 30) & 0x1FF;
    uint64_t start_virt_addr_level_2_index = (next_heap_addr >> 21) & 0x1FF;
    uint64_t start_virt_addr_level_1_index = (next_heap_addr >> 12) & 0x1FF;
    page_frame_entry_t *tmp = NULL;
    cos_process_t *tmp_process = (cos_process_t *)scheduling_properties.process_list;

    if (!tmp_process || !tmp_process->page_table)
        return 0;

    consecutive_virt_addr_found = size >> 12;

    if (size & 0xFFF)
        ++consecutive_virt_addr_found;

    total_frames = consecutive_virt_addr_found;

    if (!allocate_memory_blocs(consecutive_virt_addr_found, false, &tmp_process->allocated_page_reserved, &tmp_process->allocated_process_memory))
        return 0;

    tmp = tmp_process->allocated_process_memory;
    for (uint64_t level_4_index = start_virt_addr_level_4_index; level_4_index < PAGE_TABLE_ENTRY_COUNT; ++level_4_index) {

        //The bit expansion of the address is made due to the limitation of the architecture.
        if (level_4_index & 0b11110000) {
            duplicated = (level_4_index & 0b11110000) >> 4;
            duplicated = (duplicated << 12) + (duplicated << 8) + (duplicated << 4) + duplicated;
        } else {
            duplicated = (duplicated << 12) + (duplicated << 8) + (duplicated << 4) + duplicated;
        }

        if (!tmp_process->page_table->entries[level_4_index]) {
            if (!allocate_memory_blocs(1, true, &tmp_process->allocated_page_reserved, &tmp_process->allocated_process_memory))
                return 0;
            tmp_process->page_table->entries[level_4_index] = tmp_process->allocated_page_reserved->address | 0b111;
            tmp_process->allocated_page_reserved->virt_addr = PML4_ENTRY(level_4_index);
            memset((void *)(PML4_ENTRY(level_4_index) & ~0xfff), 0, sizeof(page_table_t));
        }

        for (uint64_t level_3_index = start_virt_addr_level_3_index; level_3_index < PAGE_TABLE_ENTRY_COUNT; ++level_3_index) {

                if (!((page_table_t *)PML4_ENTRY(level_4_index))->entries[level_3_index]) {
                    if (!allocate_memory_blocs(1, true, &tmp_process->allocated_page_reserved, &tmp_process->allocated_process_memory))
                        return 0;
                    ((page_table_t *)PML4_ENTRY(level_4_index))->entries[level_3_index] = tmp_process->allocated_page_reserved->address | 0b111;
                    tmp_process->allocated_page_reserved->virt_addr = PUD_ENTRY(level_4_index, level_3_index);
                    memset((void *)(PUD_ENTRY(level_4_index, level_3_index) & ~0xfff), 0, sizeof(pmd_entry_t));
                }

            for (uint64_t level_2_index = start_virt_addr_level_2_index; level_2_index < PAGE_TABLE_ENTRY_COUNT; ++level_2_index) {

                if (!((page_table_t *)PUD_ENTRY(level_4_index, level_3_index))->entries[level_2_index]) {
                    if (!allocate_memory_blocs(1, true, &tmp_process->allocated_page_reserved, &tmp_process->allocated_process_memory))
                        return 0;
                    ((page_table_t *)PUD_ENTRY(level_4_index, level_3_index))->entries[level_2_index] = tmp_process->allocated_page_reserved->address | 0b111;
                    tmp_process->allocated_page_reserved->virt_addr = PMD_ENTRY(level_4_index, level_3_index, level_2_index);
                    memset((void *)(PMD_ENTRY(level_4_index, level_3_index, level_2_index) & ~0xfff), 0, sizeof(pmd_entry_t));
                }

                for (uint64_t level_1_index = start_virt_addr_level_1_index; level_1_index < PAGE_TABLE_ENTRY_COUNT; ++level_1_index) {

                    ((page_table_t *)(PMD_ENTRY(level_4_index, level_3_index, level_2_index)))->entries[level_1_index] = tmp->address | 0b111;
                    tmp->virt_addr = duplicated << 48 |
                        (level_4_index & 0b111111111) << 39 |
                        (level_3_index & 0b111111111) << 30 |
                        (level_2_index & 0b111111111) << 21 |
                        (level_1_index & 0b111111111) << 12 |
                        0;

                    if (!--consecutive_virt_addr_found)
                        break;
                    tmp = tmp->next_frame;
                }

                start_virt_addr_level_1_index = 0;
                if (!consecutive_virt_addr_found)
                    break;
            }

            start_virt_addr_level_2_index = 0;
            if (!consecutive_virt_addr_found)
                break;
        }

        start_virt_addr_level_3_index = 0;
        if (!consecutive_virt_addr_found)
            break;
    }
    tmp_process->heap_end += total_frames * DEFAULT_BLOCK_SIZE;
    return total_frames;
}

page_table_t *kernel_make_process_page_table(cos_process_t * proc)
{
    page_table_t *new_table = NULL;

    //Should this block be put into the kernel instead?
    allocate_memory_blocs(1, 1, &proc->allocated_page_reserved, &proc->allocated_process_memory);
    new_table = (page_table_t *)kernel_map(proc->allocated_page_reserved, 1);
    memset(new_table, 0, sizeof(page_table_t));
    new_table->entries[510] = proc->allocated_page_reserved->address | 0b111;
    new_table->entries[511] = scheduling_properties.kernel_process.page_table->entries[511];
    return new_table;
}

uint64_t map_process_section(uint64_t virt_addr, uint64_t size)
{
    init_process_section(scheduling_properties.process_list, virt_addr & ~0xFFF);
    if (DEFAULT_BLOCK_SIZE < size)
    {
        virt_addr = (virt_addr & ~0xFFF) + DEFAULT_BLOCK_SIZE;
        expand_section(virt_addr, size - DEFAULT_BLOCK_SIZE);
    } else if (DEFAULT_BLOCK_SIZE < (size + (virt_addr & 0xFFF)))
    {
        virt_addr = (virt_addr & ~0xFFF) + DEFAULT_BLOCK_SIZE;
        expand_section(virt_addr, (size + (virt_addr & 0xFFF)) - DEFAULT_BLOCK_SIZE);
    }
	memset((void *)virt_addr, 0, size);
    return virt_addr;
}

//ALL USERSPACE ADDRESSES SHOULD BE LOCATED IN LOWER HALF MEMORY. NO EXCEPTIONS.
//If all lower half virtual memory addresses have been mapped, it means almost 256TB of RAM have been allocated for userspace program usage.
//This case should realistically never happen.
//If it does, free memory instead before calling this function again.

//TODO: Change page_frame_t structures to return a better structure containing every single physical addresses.
//TODO: I realised that expanded page table blocks are identity mapped.
//      This behavior will have to be changed later down the line.

//This function is actually unused because regions are mapped without an mmap equivalent.
/*
uint64_t cos_mmap(page_table_t *table, page_frame_entry_t *allocated, uint64_t nb_frames)
{
    uint64_t virt_addr = 0;
    uint64_t duplicated = 0;
    uint64_t consecutive_virt_addr_found = 0;
    page_frame_entry_t *tmp = allocated;

    if (table == NULL) {
        cos_printf("COS_MMAP: The PML4 pointer wasn't initialised.");
        return (uint64_t)-1;
    }

    for (uint64_t level_4_index = 0; level_4_index < PAGE_TABLE_ENTRY_COUNT; ++level_4_index) {

        //Bit expansion of the address is made due to the limititation of the architecture.
        if (level_4_index & 0b11110000) {
            duplicated = (level_4_index & 0b11110000) >> 4;
            duplicated = (duplicated << 12) + (duplicated << 8) + (duplicated << 4) + duplicated;
        } else {
            duplicated = (duplicated << 12) + (duplicated << 8) + (duplicated << 4) + duplicated;
        }

        if ((table->entries[level_4_index] & ~((duplicated << 48) | 0xfff)) == 0) {
            allocate_memory_blocs(1, true, properties.process_list->allocated_page_reserved, properties.process_list->allocated_process_memory);
            table->entries[level_4_index] = properties.process_list->allocated_page_reserved->address | 0b111;
            properties.process_list->allocated_page_reserved->virt_addr = PML4_ENTRY(level_4_index);
            memset((void *)PML4_ENTRY(level_4_index), 0, DEFAULT_BLOCK_SIZE);
        }

        page_table_t *table_level_3 = (page_table_t *)(PML4_ENTRY(level_4_index) & ~0xfff);
        pgd_entry_t *table_pgd_entry = (pgd_entry_t *)table_level_3;

        if (!table_pgd_entry->present || !table_pgd_entry->read_write) {
            table_pgd_entry->present = 1;
            table_pgd_entry->read_write = 1;
            table_pgd_entry->user_supervisor = 1;
        }

        for (uint64_t level_3_index = 0; level_3_index < PAGE_TABLE_ENTRY_COUNT; ++level_3_index) {

            if ((table_level_3->entries[level_3_index] & ~((duplicated << 48) | 0xfff)) == 0) {
                allocate_memory_blocs(1, true, properties.process_list->allocated_page_reserved, properties.process_list->allocated_process_memory);
                table_level_3->entries[level_3_index] = properties.process_list->allocated_page_reserved->address | 0b111;
                properties.process_list->allocated_page_reserved->virt_addr = PUD_ENTRY(level_4_index, level_3_index);
                memset((void *)(PUD_ENTRY(level_4_index, level_3_index) & ~0xfff), 0, DEFAULT_BLOCK_SIZE);
            }

            page_table_t *table_level_2 = (page_table_t *)(PUD_ENTRY(level_4_index, level_3_index) & ~0xfff);
            pud_entry_t *table_pud_entry = (pud_entry_t *)table_level_2;

            if (!table_pud_entry->present || !table_pud_entry->read_write) {
                table_pud_entry->present = 1;
                table_pud_entry->read_write = 1;
                table_pud_entry->user_supervisor = 1;
            }

            for (uint64_t level_2_index = 0; level_2_index < PAGE_TABLE_ENTRY_COUNT; ++level_2_index) {

                if ((table_level_2->entries[level_2_index] & ~((duplicated << 48) | 0xfff)) == 0) {

                    allocate_memory_blocs(1, true, properties.process_list->allocated_page_reserved, properties.process_list->allocated_process_memory);
                    table_level_2->entries[level_2_index] = properties.process_list->allocated_page_reserved->address | 0b111;
                    properties.process_list->allocated_page_reserved->virt_addr = PMD_ENTRY(level_4_index, level_3_index, level_2_index);
                    memset((void *)(PMD_ENTRY(level_4_index, level_3_index, level_2_index) & ~0xfff), 0, DEFAULT_BLOCK_SIZE);
                }

                page_table_t *table_level_1 = (page_table_t *)(PMD_ENTRY(level_4_index, level_3_index, level_2_index) & ~0xfff);
                pmd_entry_t *table_pmd_entry = (pmd_entry_t *)table_level_1;

                if (!table_pmd_entry->present || !table_pmd_entry->read_write) {
                    table_pud_entry->present = 1;
                    table_pud_entry->read_write = 1;
                    table_pud_entry->user_supervisor = 1;
                }

                for (uint64_t level_1_index = 0; level_1_index < PAGE_TABLE_ENTRY_COUNT; ++level_1_index) {
                    uint64_t table_pt_entry_value = table_level_1->entries[level_1_index];
                    pt_entry_t table_pt_entry;

                    cos_memcpy(&table_pt_entry, &table_pt_entry_value, sizeof(uint64_t));

                    if (table_pt_entry.present || table_pt_entry.read_write) {
                        consecutive_virt_addr_found = 0;
                        virt_addr = 0;
                        continue;
                    }

                    if (virt_addr == 0) {
                        virt_addr =
                            duplicated << 48 |
                            (level_4_index & 0b111111111) << 39 |
                            (level_3_index & 0b111111111) << 30 |
                            (level_2_index & 0b111111111) << 21 |
                            (level_1_index & 0b111111111) << 12 |
                            0;
                    }

                    if (++consecutive_virt_addr_found == nb_frames) {
                        uint64_t start_virt_addr_level_4_index = (virt_addr >> 39) & 0x1FF;
                        uint64_t start_virt_addr_level_3_index = (virt_addr >> 30) & 0x1FF;
                        uint64_t start_virt_addr_level_2_index = (virt_addr >> 21) & 0x1FF;
                        uint64_t start_virt_addr_level_1_index = (virt_addr >> 12) & 0x1FF;

                        for (level_4_index = start_virt_addr_level_4_index; level_4_index < PAGE_TABLE_ENTRY_COUNT; ++level_4_index) {

                            if (level_4_index & 0b11110000) {
                                duplicated = (level_4_index & 0b11110000) >> 4;
                                duplicated = (duplicated << 12) + (duplicated << 8) + (duplicated << 4) + duplicated;
                            } else {
                                duplicated = (duplicated << 12) + (duplicated << 8) + (duplicated << 4) + duplicated;
                            }

                            for (level_3_index = start_virt_addr_level_3_index; level_3_index < PAGE_TABLE_ENTRY_COUNT; ++level_3_index) {

                                for (level_2_index = start_virt_addr_level_2_index; level_2_index < PAGE_TABLE_ENTRY_COUNT; ++level_2_index) {

                                    for (level_1_index = start_virt_addr_level_1_index; level_1_index < PAGE_TABLE_ENTRY_COUNT; ++level_1_index) {

                                        ((page_table_t *)(PMD_ENTRY(level_4_index, level_3_index, level_2_index)))->entries[level_1_index] = (tmp->address | 0b111);
                                        tmp->virt_addr = duplicated << 48 |
                                        (level_4_index & 0b111111111) << 39 |
                                        (level_3_index & 0b111111111) << 30 |
                                        (level_2_index & 0b111111111) << 21 |
                                        (level_1_index & 0b111111111) << 12 |
                                        0;

                                        tmp = tmp->next_frame;
                                        if (!--consecutive_virt_addr_found)
                                            break;
                                    }

                                    start_virt_addr_level_1_index = 0;
                                    if (!consecutive_virt_addr_found)
                                        break;
                                }

                                start_virt_addr_level_2_index = 0;
                                if (!consecutive_virt_addr_found)
                                    break;
                            }

                            start_virt_addr_level_3_index = 0;
                            if (!consecutive_virt_addr_found)
                                break;
                        }

                        return virt_addr;
                    }
                }
            }
        }
    }

    cos_term_set_color(COS_VGA_ENTRY_COLOR(COS_VGA_COLOR_RED, COS_VGA_COLOR_BLACK));
    cos_printf("KERNEL_WARNING: Kernel page table out of available virtual addresses starting from %d\n", 0x1000);
    cos_printf("KERNEL_WARNING: Pages should be unmapped first or blocks should be freed.\n");
    cos_term_set_color(COS_VGA_DEFAULT_COLOR);
    return (uint64_t)-1;
}
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define TRUE 1
#define FALSE 0
#define MAX_TLB_ENTRIES 8
#define MAX_PROCESSES 4
#define INVALID_ADDRESS UINT32_MAX

typedef struct {
    int valid;
    uint32_t vpn;
    uint32_t pfn;
    uint32_t pid;       // Include PID in TLB entry
    uint32_t timestamp;
} TLBEntry;

typedef struct {
    int valid;
    uint32_t pfn;
} PageTableEntry;

// Global variables for the simulation
FILE* output_file;
char* strategy;
uint32_t* memory;
TLBEntry tlb[MAX_TLB_ENTRIES]; // Only one TLB
PageTableEntry page_tables[MAX_PROCESSES][1024]; // assuming a maximum of 1024 pages
uint32_t registers[2]; // registers r1 and r2
uint32_t process_registers[MAX_PROCESSES][2]; // For storing r1 and r2 of each process
int current_pid = 0;
uint32_t instruction_counter = 0;
int offset_bits;
int pfn_bits;
int vpn_bits;
int is_defined = FALSE; // Flag to check if 'define' has been called

void initialize_memory(int offset, int pfn, int vpn) {
    offset_bits = offset;
    pfn_bits = pfn;
    vpn_bits = vpn;

    int memory_size = (1 << (offset_bits + pfn_bits));
    memory = (uint32_t*)calloc(memory_size, sizeof(uint32_t));
    if (!memory) {
        fprintf(stderr, "Memory allocation failed.\n");
        exit(1);
    }

    // Initialize TLB entries
    for (int i = 0; i < MAX_TLB_ENTRIES; i++) {
        tlb[i].valid = FALSE;
    }

    // Initialize page tables for each process
    for (int pid = 0; pid < MAX_PROCESSES; pid++) {
        for (int i = 0; i < 1024; i++) {
            page_tables[pid][i].valid = FALSE;
            page_tables[pid][i].pfn = 0; // Initialize pfn to 0
        }
        // Initialize process registers
        process_registers[pid][0] = 0; // r1
        process_registers[pid][1] = 0; // r2
    }

    // Include 'Current PID' prefix in the output of 'define'
    fprintf(output_file, "Current PID: %d. Memory instantiation complete. OFF bits: %d. PFN bits: %d. VPN bits: %d\n", current_pid, offset, pfn, vpn);
}

void context_switch(int pid) {
    if (pid < 0 || pid >= MAX_PROCESSES) {
        // Include 'Current PID' prefix in error messages
        fprintf(output_file, "Current PID: %d. Invalid context switch to process %d\n", current_pid, pid);
        exit(1);
    }

    // Save current process's registers
    process_registers[current_pid][0] = registers[0];
    process_registers[current_pid][1] = registers[1];

    current_pid = pid; // Update current_pid before printing

    // Restore new process's registers
    registers[0] = process_registers[current_pid][0];
    registers[1] = process_registers[current_pid][1];

    // Include 'Current PID' prefix and correct formatting
    fprintf(output_file, "Current PID: %d. Switched execution context to process: %d\n", current_pid, pid);
}

// Function to handle 'map' command
void handle_map(char **tokens) {
    uint32_t vpn = (uint32_t)atoi(tokens[1]);
    uint32_t pfn = (uint32_t)atoi(tokens[2]);

    // Update the page table for the current process
    page_tables[current_pid][vpn].valid = TRUE;
    page_tables[current_pid][vpn].pfn = pfn;

    // Invalidate any existing TLB entries for this VPN and PID
    for (int i = 0; i < MAX_TLB_ENTRIES; i++) {
        if (tlb[i].valid && tlb[i].vpn == vpn && tlb[i].pid == current_pid) {
            tlb[i].valid = FALSE;
            // Do not break; there might be multiple entries
        }
    }

    // The new mapping must be created both in the TLB and the page table
    // Find an invalid TLB entry starting from index 0
    int replace_index = -1;
    for (int i = 0; i < MAX_TLB_ENTRIES; i++) {
        if (!tlb[i].valid) {
            replace_index = i;
            break;
        }
    }

    // If no invalid entry, use replacement strategy
    if (replace_index == -1) {
        uint32_t target_timestamp = UINT32_MAX;
        if (strcmp(strategy, "FIFO") == 0 || strcmp(strategy, "fifo") == 0) {
            // FIFO strategy: replace the oldest entry
            for (int i = 0; i < MAX_TLB_ENTRIES; i++) {
                if (tlb[i].timestamp < target_timestamp) {
                    target_timestamp = tlb[i].timestamp;
                    replace_index = i;
                }
            }
        } else if (strcmp(strategy, "LRU") == 0 || strcmp(strategy, "lru") == 0) {
            // LRU strategy: replace the least recently used entry
            for (int i = 0; i < MAX_TLB_ENTRIES; i++) {
                if (tlb[i].timestamp < target_timestamp) {
                    target_timestamp = tlb[i].timestamp;
                    replace_index = i;
                }
            }
        } else {
            fprintf(output_file, "Error: unknown TLB replacement strategy %s\n", strategy);
            exit(1);
        }
    }

    // Replace the entry at replace_index
    tlb[replace_index].valid = TRUE;
    tlb[replace_index].vpn = vpn;
    tlb[replace_index].pfn = pfn;
    tlb[replace_index].pid = current_pid;
    tlb[replace_index].timestamp = instruction_counter;

    fprintf(output_file, "Current PID: %d. Mapped virtual page number %u to physical frame number %u\n", current_pid, vpn, pfn);
}

// Function to handle 'unmap' command
void handle_unmap(char **tokens) {
    uint32_t vpn = (uint32_t)atoi(tokens[1]);

    // Invalidate the page table entry for the current process
    page_tables[current_pid][vpn].valid = FALSE;
    page_tables[current_pid][vpn].pfn = 0; // Reset PFN to 0

    // Invalidate any TLB entry for this VPN and current PID
    for (int i = 0; i < MAX_TLB_ENTRIES; i++) {
        if (tlb[i].valid && tlb[i].vpn == vpn && tlb[i].pid == current_pid) {
            tlb[i].valid = FALSE;
            // Do not break; there might be multiple entries
        }
    }

    fprintf(output_file, "Current PID: %d. Unmapped virtual page number %u\n", current_pid, vpn);
}

// Function to translate virtual address to physical address
uint32_t translate_address(uint32_t virtual_addr) {
    uint32_t vpn = virtual_addr >> offset_bits;
    uint32_t offset = virtual_addr & ((1 << offset_bits) - 1);

    // TLB lookup
    int tlb_index = -1;
    int tlb_hit = FALSE;

    for (int i = 0; i < MAX_TLB_ENTRIES; i++) {
        if (tlb[i].valid && tlb[i].vpn == vpn && tlb[i].pid == current_pid) {
            tlb_hit = TRUE;
            tlb_index = i;
            break;
        }
    }

    if (tlb_hit) {
        // TLB hit
        uint32_t pfn = tlb[tlb_index].pfn;
        fprintf(output_file, "Current PID: %d. Translating. Lookup for VPN %u hit in TLB entry %d. PFN is %u\n", current_pid, vpn, tlb_index, pfn);

        // For LRU strategy, update timestamp
        if (strcmp(strategy, "LRU") == 0 || strcmp(strategy, "lru") == 0) {
            tlb[tlb_index].timestamp = instruction_counter;
        }

        return (pfn << offset_bits) | offset;
    } else {
        // TLB miss
        fprintf(output_file, "Current PID: %d. Translating. Lookup for VPN %u caused a TLB miss\n", current_pid, vpn);

        // Page table lookup
        PageTableEntry pte = page_tables[current_pid][vpn];
        if (pte.valid) {
            uint32_t pfn = pte.pfn;
            fprintf(output_file, "Current PID: %d. Translating. Successfully mapped VPN %u to PFN %u\n", current_pid, vpn, pfn);

            // Bring the mapping into the TLB
            int replace_index = -1;

            // Find an invalid TLB entry starting from index 0
            for (int i = 0; i < MAX_TLB_ENTRIES; i++) {
                if (!tlb[i].valid) {
                    replace_index = i;
                    break;
                }
            }

            // If no invalid entry, use replacement strategy
            if (replace_index == -1) {
                uint32_t target_timestamp = UINT32_MAX;
                if (strcmp(strategy, "FIFO") == 0 || strcmp(strategy, "fifo") == 0) {
                    // FIFO strategy: replace the oldest entry
                    target_timestamp = UINT32_MAX;
                    for (int i = 0; i < MAX_TLB_ENTRIES; i++) {
                        if (tlb[i].timestamp < target_timestamp) {
                            target_timestamp = tlb[i].timestamp;
                            replace_index = i;
                        }
                    }
                } else if (strcmp(strategy, "LRU") == 0 || strcmp(strategy, "lru") == 0) {
                    // LRU strategy: replace the least recently used entry
                    target_timestamp = UINT32_MAX;
                    for (int i = 0; i < MAX_TLB_ENTRIES; i++) {
                        if (tlb[i].timestamp < target_timestamp) {
                            target_timestamp = tlb[i].timestamp;
                            replace_index = i;
                        }
                    }
                } else {
                    fprintf(output_file, "Error: unknown TLB replacement strategy %s\n", strategy);
                    exit(1);
                }
            }

            // Replace the entry at replace_index
            tlb[replace_index].valid = TRUE;
            tlb[replace_index].vpn = vpn;
            tlb[replace_index].pfn = pfn;
            tlb[replace_index].pid = current_pid;
            tlb[replace_index].timestamp = instruction_counter;

            return (pfn << offset_bits) | offset;
        } else {
            // Translation not found in page table
            fprintf(output_file, "Current PID: %d. Translating. Translation for VPN %u not found in page table\n", current_pid, vpn);
            exit(1);
        }
    }
}

// Function to handle 'load' instruction
void handle_load(char **tokens) {
    char *dst = tokens[1];
    char *src = tokens[2];

    // Validate destination register
    int reg_index;
    if (strcmp(dst, "r1") == 0) {
        reg_index = 0;
    } else if (strcmp(dst, "r2") == 0) {
        reg_index = 1;
    } else {
        fprintf(output_file, "Current PID: %d. Error: invalid register operand %s\n", current_pid, dst);
        exit(1);
    }

    // Check if src is immediate or memory location
    if (src[0] == '#') {
        // Immediate value
        uint32_t value = (uint32_t)atoi(src + 1);
        registers[reg_index] = value;
        fprintf(output_file, "Current PID: %d. Loaded immediate %s into register %s\n", current_pid, src + 1, dst);
    } else {
        // Memory location
        uint32_t src_addr = (uint32_t)atoi(src); // Virtual address

        // Perform address translation
        uint32_t physical_addr = translate_address(src_addr);

        // Check if translation was successful
        if (physical_addr == INVALID_ADDRESS) {
            // Error message is already printed in translate_address
            exit(1);
        }

        // Load the value from memory
        uint32_t value = memory[physical_addr];
        registers[reg_index] = value;

        fprintf(output_file, "Current PID: %d. Loaded value of location %s (%u) into register %s\n", current_pid, src, value, dst);
    }
}

// Function to handle 'store' instruction
void handle_store(char **tokens) {
    char *dst_str = tokens[1]; // Virtual address as string
    char *src = tokens[2];

    uint32_t dst_addr = (uint32_t)atoi(dst_str); // Virtual address

    // Perform address translation
    uint32_t physical_addr = translate_address(dst_addr);

    // Check if translation was successful
    if (physical_addr == INVALID_ADDRESS) {
        // Error message is already printed in translate_address
        exit(1);
    }

    // Get the value to store
    uint32_t value;

    if (src[0] == '#') {
        // Immediate value
        value = (uint32_t)atoi(src + 1);
        fprintf(output_file, "Current PID: %d. Stored immediate %s into location %s\n", current_pid, src + 1, dst_str);
    } else if (strcmp(src, "r1") == 0 || strcmp(src, "r2") == 0) {
        // Register value
        int reg_index = (strcmp(src, "r1") == 0) ? 0 : 1;
        value = registers[reg_index];
        fprintf(output_file, "Current PID: %d. Stored value of register %s (%u) into location %s\n", current_pid, src, value, dst_str);
    } else {
        fprintf(output_file, "Current PID: %d. Error: invalid register operand %s\n", current_pid, src);
        exit(1);
    }

    // Store the value into memory
    memory[physical_addr] = value;
}

// Function to handle 'add' instruction
void handle_add() {
    uint32_t value1 = registers[0]; // r1
    uint32_t value2 = registers[1]; // r2
    uint32_t result = value1 + value2;
    registers[0] = result; // Store result in r1

    // Corrected output string to match expected output
    fprintf(output_file, "Current PID: %d. Added contents of registers r1 (%u) and r2 (%u). Result: %u\n", current_pid, value1, value2, result);
}

// Function to handle 'pinspect' instruction
void handle_pinspect(char **tokens) {
    uint32_t vpn = (uint32_t)atoi(tokens[1]);

    PageTableEntry pte = page_tables[current_pid][vpn];
    uint32_t pfn = pte.pfn;
    int valid = pte.valid;

    fprintf(output_file, "Current PID: %d. Inspected page table entry %u. Physical frame number: %u. Valid: %d\n", current_pid, vpn, pfn, valid);
}

// Function to handle 'tinspect' instruction
void handle_tinspect(char **tokens) {
    int tlb_index = atoi(tokens[1]);

    if (tlb_index < 0 || tlb_index >= MAX_TLB_ENTRIES) {
        fprintf(output_file, "Current PID: %d. Error: invalid TLB index %d\n", current_pid, tlb_index);
        exit(1);
    }

    TLBEntry entry = tlb[tlb_index];

    uint32_t vpn = entry.vpn;
    uint32_t pfn = entry.pfn;
    int valid = entry.valid;
    uint32_t pid = entry.pid;
    uint32_t timestamp = entry.timestamp;

    fprintf(output_file, "Current PID: %d. Inspected TLB entry %d. VPN: %u. PFN: %u. Valid: %d. PID: %u. Timestamp: %u\n",
            current_pid, tlb_index, vpn, pfn, valid, pid, timestamp);
}

// Function to handle 'linspect' instruction
void handle_linspect(char **tokens) {
    uint32_t physical_addr = (uint32_t)atoi(tokens[1]);

    // Check if physical address is within bounds
    uint32_t memory_size = (1 << (offset_bits + pfn_bits));
    if (physical_addr >= memory_size) {
        fprintf(output_file, "Current PID: %d. Error: invalid physical address %u\n", current_pid, physical_addr);
        exit(1);
    }

    uint32_t value = memory[physical_addr];

    // Updated output message to match expected output
    fprintf(output_file, "Current PID: %d. Inspected physical location %u. Value: %u\n", current_pid, physical_addr, value);
}

// Function to handle 'rinspect' instruction
void handle_rinspect(char **tokens) {
    char *reg = tokens[1];

    int reg_index;
    if (strcmp(reg, "r1") == 0) {
        reg_index = 0;
    } else if (strcmp(reg, "r2") == 0) {
        reg_index = 1;
    } else {
        fprintf(output_file, "Current PID: %d. Error: invalid register operand %s\n", current_pid, reg);
        exit(1);
    }

    uint32_t value = registers[reg_index];

    fprintf(output_file, "Current PID: %d. Inspected register %s. Content: %u\n", current_pid, reg, value);
}

// Function to tokenize input
char** tokenize_input(char* input) {
    char** tokens = NULL;
    char* token = strtok(input, " ");
    int num_tokens = 0;

    while (token != NULL) {
        num_tokens++;
        tokens = realloc(tokens, num_tokens * sizeof(char*));
        if (!tokens) {
            fprintf(stderr, "Memory allocation failed during tokenization.\n");
            exit(1);
        }
        tokens[num_tokens - 1] = malloc(strlen(token) + 1);
        if (!tokens[num_tokens - 1]) {
            fprintf(stderr, "Memory allocation failed during tokenization.\n");
            exit(1);
        }
        strcpy(tokens[num_tokens - 1], token);
        token = strtok(NULL, " ");
    }

    num_tokens++;
    tokens = realloc(tokens, num_tokens * sizeof(char*));
    tokens[num_tokens - 1] = NULL;

    return tokens;
}

int main(int argc, char* argv[]) {
    const char usage[] = "Usage: memsym.out <strategy> <input trace> <output trace>\n";
    char* input_trace;
    char* output_trace;
    char buffer[1024];

    if (argc != 4) {
        printf("%s", usage);
        return 1;
    }
    strategy = argv[1];
    input_trace = argv[2];
    output_trace = argv[3];

    FILE* input_file = fopen(input_trace, "r");
    output_file = fopen(output_trace, "w");

    if (!input_file || !output_file) {
        fprintf(stderr, "Error: unable to open input/output files.\n");
        return 1;
    }

    while (!feof(input_file)) {
        char* rez = fgets(buffer, sizeof(buffer), input_file);
        if (!rez) {
            break;
        }

        buffer[strcspn(buffer, "\n")] = '\0'; // Remove newline character

        if (buffer[0] == '%') continue; // Skip comments

        // Skip empty lines
        if (buffer[0] == '\0') continue;

        // Increment instruction counter before processing
        instruction_counter++;

        char** tokens = tokenize_input(buffer);

        if (strcmp(tokens[0], "define") == 0) {
            if (is_defined) {
                // Include 'Current PID' prefix in the error message
                fprintf(output_file, "Current PID: %d. Error: multiple calls to define in the same trace\n", current_pid);
                break;
            }
            int offset = atoi(tokens[1]);
            int pfn = atoi(tokens[2]);
            int vpn = atoi(tokens[3]);
            initialize_memory(offset, pfn, vpn);
            is_defined = TRUE;
        } else if (!is_defined) {
            // Include 'Current PID' prefix in this error message
            fprintf(output_file, "Current PID: %d. Error: attempt to execute instruction before define\n", current_pid);
            break;
        } else if (strcmp(tokens[0], "ctxswitch") == 0) {
            int pid = atoi(tokens[1]);
            context_switch(pid);
        } else if (strcmp(tokens[0], "map") == 0) {
            handle_map(tokens);
        } else if (strcmp(tokens[0], "unmap") == 0) {
            handle_unmap(tokens);
        } else if (strcmp(tokens[0], "load") == 0) {
            handle_load(tokens);
        } else if (strcmp(tokens[0], "store") == 0) {
            handle_store(tokens);
        } else if (strcmp(tokens[0], "add") == 0) {
            handle_add();
        } else if (strcmp(tokens[0], "pinspect") == 0) {
            handle_pinspect(tokens);
        } else if (strcmp(tokens[0], "tinspect") == 0) {
            handle_tinspect(tokens);
        } else if (strcmp(tokens[0], "linspect") == 0) {
            handle_linspect(tokens);
        } else if (strcmp(tokens[0], "rinspect") == 0) {
            handle_rinspect(tokens);
        } else {
            fprintf(output_file, "Error: unknown instruction %s\n", tokens[0]);
            exit(1);
        }

        // Deallocate tokens
        for (int i = 0; tokens[i] != NULL; i++)
            free(tokens[i]);
        free(tokens);
    }

    fclose(input_file);
    fclose(output_file);

    free(memory);
    return 0;
}

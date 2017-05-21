#ifndef _TERMINAL_CONTROL_VM_H_
#define _TERMINAL_CONTROL_VM_H_

#include "structs.h"
#include "types.h"
#include "vm_instructions.h"

struct VM {
    struct Context *ctx;
    size_t mem_size;
    u16 regs[16];
    u8 *mem;
    u8 *ip;
};

void tc_vm_init(struct Context *ctx, struct VM *vm, size_t mem_size) {
    size_t i;
    vm -> ctx = ctx;
    vm -> mem_size = mem_size;
    vm -> mem = (u8 *) ctx -> malloc(mem_size);
    for(i = 0; i < mem_size; i++) {
        vm -> mem[i] = VMI_HALT;
    }
    vm -> ip = vm -> mem;
}

void tc_vm_reset(struct VM *vm) {
    vm -> ip = vm -> mem;
}

void tc_vm_destroy(struct VM *vm) {
    vm -> ctx -> free((char *) vm -> mem);
    vm -> mem = NULL;
    vm -> mem_size = 0;
    vm -> ip = NULL;
    vm -> ctx = NULL;
}

u8 tc_vm_execute_once(struct VM *vm) {
    switch(*(vm -> ip)) {
        case VMI_NOP:
            vm -> ip++;
            break;
        
        case VMI_MOV:
            vm -> ip++;
            vm -> regs[*(vm -> ip)] = vm -> regs[*(vm -> ip + 1)];
            vm -> ip += 2;
            break;
        
        case VMI_LOAD:
            vm -> ip++;
            vm -> regs[*(vm -> ip)] = vm -> mem[*(u16 *)(vm -> ip + 1)];
            vm -> ip += 3;
            break;
        
        case VMI_STORE:
            vm -> ip++;
            vm -> mem[*(u16 *)(vm -> ip + 1)] = vm -> regs[*(vm -> ip)];
            vm -> ip += 3;
            break;
        
        case VMI_ADD:
            vm -> ip++;
            vm -> regs[0] = vm -> regs[*(vm -> ip)] + vm -> regs[*(vm -> ip + 1)];
            vm -> ip += 2;
            break;
        
        case VMI_SUB:
            vm -> ip++;
            vm -> regs[0] = vm -> regs[*(vm -> ip)] - vm -> regs[*(vm -> ip + 1)];
            vm -> ip += 2;
            break;
        
        case VMI_MUL:
            vm -> ip++;
            vm -> regs[0] = vm -> regs[*(vm -> ip)] * vm -> regs[*(vm -> ip + 1)];
            vm -> ip += 2;
            break;
        
        case VMI_DIV:
            vm -> ip++;
            vm -> regs[0] = vm -> regs[*(vm -> ip)] / vm -> regs[*(vm -> ip + 1)];
            vm -> ip += 2;
            break;
        
        case VMI_SHL:
            vm -> ip++;
            vm -> regs[0] = vm -> regs[*(vm -> ip)] << vm -> regs[*(vm -> ip + 1)];
            vm -> ip += 2;
            break;
        
        case VMI_SHR:
            vm -> ip++;
            vm -> regs[0] = vm -> regs[*(vm -> ip)] >> vm -> regs[*(vm -> ip + 1)];
            vm -> ip += 2;
            break;

        case VMI_AND:
            vm -> ip++;
            vm -> regs[0] = vm -> regs[*(vm -> ip)] & vm -> regs[*(vm -> ip + 1)];
            vm -> ip += 2;
            break;
        
        case VMI_OR:
            vm -> ip++;
            vm -> regs[0] = vm -> regs[*(vm -> ip)] | vm -> regs[*(vm -> ip + 1)];
            vm -> ip += 2;
            break;

        case VMI_XOR:
            vm -> ip++;
            vm -> regs[0] = vm -> regs[*(vm -> ip)] ^ vm -> regs[*(vm -> ip + 1)];
            vm -> ip += 2;
            break;
        
        case VMI_GT:
            vm -> ip++;
            vm -> regs[0] = (vm -> regs[*(vm -> ip)] > vm -> regs[*(vm -> ip + 1)]);
            vm -> ip += 2;
            break;
        
        case VMI_LT:
            vm -> ip++;
            vm -> regs[0] = (vm -> regs[*(vm -> ip)] < vm -> regs[*(vm -> ip + 1)]);
            vm -> ip += 2;
            break;
        
        case VMI_EQ:
            vm -> ip++;
            vm -> regs[0] = (vm -> regs[*(vm -> ip)] == vm -> regs[*(vm -> ip + 1)]);
            vm -> ip += 2;
            break;

        case VMI_JMP:
            vm -> ip++;
            vm -> ip = vm -> mem + vm -> mem[*(u16 *)(vm -> ip)];
            break;
        
        case VMI_CONDJMP:
            vm -> ip++;
            if(vm -> regs[*(vm -> ip)]) {
                vm -> ip++;
                vm -> ip = vm -> mem + vm -> mem[*(u16 *)(vm -> ip)];
            } else {
                vm -> ip += 3;
            }
            break;
        
        case VMI_HALT:
            return 1;
        
        case VMI_GPIO_DIGITAL_READ:
            vm -> ip++;
            vm -> regs[0] = vm -> ctx -> gpio_read(vm -> regs[*(vm -> ip)]);
            vm -> ip++;
            break;
        
        case VMI_GPIO_DIGITAL_WRITE:
            vm -> ip++;
            vm -> ctx -> gpio_write(vm -> regs[*(vm -> ip)], vm -> regs[*(vm -> ip + 1)]);
            vm -> ip += 2;
            break;
        
        default:
            tc_vm_reset(vm);
    }

    return 0;
}

u16 tc_vm_execute(struct VM *vm) {
    while(tc_vm_execute_once(vm) == 0);
    return vm -> regs[0];
}

#endif

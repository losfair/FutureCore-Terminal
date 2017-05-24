#ifndef _TERMINAL_CONTROL_VM_H_
#define _TERMINAL_CONTROL_VM_H_

#ifdef DEBUG
#include <stdio.h>
#endif

#include "structs.h"
#include "types.h"
#include "vm_instructions.h"
#include "constants.h"

void tc_vm_enter_32(struct VM *vm) {
    vm -> mode = VMA_32;

    vm -> ip = vm -> ip - vm -> code_begin + VMA_32_CODE_BEGIN;

    vm -> code_begin = VMA_32_CODE_BEGIN;
    vm -> code_end = VMA_32_CODE_END;
    vm -> stack_begin = VMA_32_STACK_BEGIN;
    vm -> stack_end = VMA_32_STACK_END;
    vm -> sp = VMA_32_STACK_BEGIN;
}

void tc_vm_enter_16(struct VM *vm) {
    vm -> mode = VMA_16;

    vm -> ip = vm -> ip - vm -> code_begin + VMA_16_CODE_BEGIN;

    vm -> code_begin = VMA_16_CODE_BEGIN;
    vm -> code_end = VMA_16_CODE_END;
    vm -> stack_begin = VMA_16_STACK_BEGIN;
    vm -> stack_end = VMA_16_STACK_END;
    vm -> sp = VMA_16_STACK_BEGIN;
}

void tc_vm_init(struct Context *ctx, struct VM *vm, size_t code_size) {
    size_t i;
    vm -> ctx = ctx;
    vm -> task_id = 0;
    vm -> error = 0;

    vm -> code_size = code_size;
    vm -> code = (u8 *) ctx -> malloc(code_size);
    for(i = 0; i < code_size; i++) {
        vm -> code[i] = VMI_HALT;
    }

    vm -> stack = (u8 *) ctx -> malloc(VM_STACK_SIZE);
    vm -> stack_size = VM_STACK_SIZE;

    vm -> hypercall_tick = NULL;
    vm -> hypercall_state = NULL;

    vm -> ip = 0;
    vm -> sp = 0;

    vm -> code_begin = 0;
    vm -> code_end = 0;
    vm -> stack_begin = 0;
    vm -> stack_end = 0;

    tc_vm_enter_16(vm);
}

void tc_vm_reset(struct VM *vm) {
    vm -> ip = 0;

    if(vm -> stack) {
        vm -> ctx -> free((char *) vm -> stack);
        vm -> stack = NULL;
        vm -> stack_size = 0;
    }
}

void tc_vm_destroy(struct VM *vm) {
    vm -> ctx -> free((char *) vm -> code);
    vm -> code = NULL;
    vm -> code_size = 0;

    if(vm -> stack) {
        vm -> ctx -> free((char *) vm -> stack);
        vm -> stack = NULL;
        vm -> stack_size = 0;
    }

    vm -> ip = 0;

    vm -> ctx = NULL;
}

u8 * tc_vm_get_real_addr(struct VM *vm, u32 vaddr, u16 flags) {
    if(/*(((flags & VMM_EXEC) && (flags & VMM_READ)) || (flags & VMM_WRITE))
        && */vaddr >= vm -> code_begin
        && vaddr < vm -> code_end
        && vaddr - vm -> code_begin < vm -> code_size
    ) {
        return (u8 *) &vm -> code[vaddr - vm -> code_begin];
    } else if(/*((flags & VMM_READ) || (flags & VMM_WRITE))
        && */vaddr >= vm -> stack_begin
        && vaddr < vm -> stack_end
        && vaddr - vm -> stack_begin < vm -> stack_size
    ) {
        return (u8 *) &vm -> stack[vaddr - vm -> stack_begin];
    } else {
#ifdef DEBUG
        printf("Error: Access violation at %p\n", (char *) (unsigned long) vaddr);
#endif
        vm -> error = VME_ACCESS_VIOLATION;
        return NULL;
    }
}

u8 tc_vm_mem_read8(struct VM *vm, u32 vaddr, u16 flags) {
    u8 *addr = tc_vm_get_real_addr(vm, vaddr, flags | VMM_READ);
    return addr ? *addr : 0;
}

u16 tc_vm_mem_read16(struct VM *vm, u32 vaddr, u16 flags) {
    u8 *addr1 = tc_vm_get_real_addr(vm, vaddr, flags | VMM_READ);
    u8 *addr2 = tc_vm_get_real_addr(vm, vaddr + 1, flags | VMM_READ);

    if(!addr1 || !addr2) {
        return 0;
    }
    return (((u16) *addr2) << 8) | ((u16) *addr1);
}

u32 tc_vm_mem_read32(struct VM *vm, u32 vaddr, u16 flags) {
    u8 *addr1 = tc_vm_get_real_addr(vm, vaddr, flags | VMM_READ);
    u8 *addr2 = tc_vm_get_real_addr(vm, vaddr + 1, flags | VMM_READ);
    u8 *addr3 = tc_vm_get_real_addr(vm, vaddr + 2, flags | VMM_READ);
    u8 *addr4 = tc_vm_get_real_addr(vm, vaddr + 3, flags | VMM_READ);

    if(!addr1 || !addr2 || !addr3 || !addr4) {
        return 0;
    }

    u32 ret = (((u32) *addr4) << 24) | (((u32) *addr3) << 16) | (((u32) *addr2) << 8) | ((u32) *addr1);

#ifdef DEBUG
    printf("mem_read32 %p: %u\n", (char *)(unsigned long) vaddr, ret);
#endif

    return ret;
}

u32 tc_vm_mem_readuint(struct VM *vm, u32 vaddr, u16 flags) {
    if(vm -> mode == VMA_16) {
        return tc_vm_mem_read16(vm, vaddr, flags);
    }
    return tc_vm_mem_read32(vm, vaddr, flags);
}

void tc_vm_mem_write8(struct VM *vm, u32 vaddr, u8 val, u16 flags) {
    u8 *addr = tc_vm_get_real_addr(vm, vaddr, flags | VMM_WRITE);
    if(addr) {
        *addr = val;
    }
}

void tc_vm_mem_write16(struct VM *vm, u32 vaddr, u16 val, u16 flags) {
    u8 *addr1 = tc_vm_get_real_addr(vm, vaddr, flags | VMM_WRITE);
    u8 *addr2 = tc_vm_get_real_addr(vm, vaddr + 1, flags | VMM_WRITE);

    if(!addr1 || !addr2) {
        return;
    }

    *addr1 = val & 0xff;
    *addr2 = val >> 8;
}

void tc_vm_mem_write32(struct VM *vm, u32 vaddr, u32 val, u16 flags) {
    u8 *addr1 = tc_vm_get_real_addr(vm, vaddr, flags | VMM_WRITE);
    u8 *addr2 = tc_vm_get_real_addr(vm, vaddr + 1, flags | VMM_WRITE);
    u8 *addr3 = tc_vm_get_real_addr(vm, vaddr + 2, flags | VMM_WRITE);
    u8 *addr4 = tc_vm_get_real_addr(vm, vaddr + 3, flags | VMM_WRITE);

    if(!addr1 || !addr2 || !addr3 || !addr4) {
        return;
    }

    *addr1 = val & 0xff;
    *addr2 = (val >> 8) & 0xff;
    *addr3 = (val >> 16) & 0xff;
    *addr4 = val >> 24;
}

void tc_vm_mem_writeuint(struct VM *vm, u32 vaddr, u32 val, u16 flags) {
    if(vm -> mode == VMA_16) {
        tc_vm_mem_write16(vm, vaddr, val, flags);
    }
    tc_vm_mem_write32(vm, vaddr, val, flags);
}

u8 tc_vm_iread8(struct VM *vm) {
    return tc_vm_mem_read8(vm, vm -> ip++, VMM_EXEC);
}

u16 tc_vm_iread16(struct VM *vm) {
    u16 ret = 0;
    ret |= tc_vm_iread8(vm);
    ret |= tc_vm_iread8(vm) << 8;
    return ret;
}

u32 tc_vm_iread32(struct VM *vm) {
    u32 ret = 0;
    ret |= tc_vm_iread8(vm);
    ret |= tc_vm_iread8(vm) << 8;
    ret |= tc_vm_iread8(vm) << 16;
    ret |= tc_vm_iread8(vm) << 24;
    return ret;
}

u32 tc_vm_ireaduint(struct VM *vm) {
    if(vm -> mode == VMA_16) {
        return tc_vm_iread16(vm);
    }
    return tc_vm_iread32(vm);
}

void tc_vm_stack_push8(struct VM *vm, u8 val) {
    tc_vm_mem_write8(vm, vm -> sp, val, VMM_WRITE);
    vm -> sp++;
}

void tc_vm_stack_push16(struct VM *vm, u16 val) {
    tc_vm_mem_write16(vm, vm -> sp, val, VMM_WRITE);
    vm -> sp += 2;
}

void tc_vm_stack_push32(struct VM *vm, u32 val) {
    tc_vm_mem_write32(vm, vm -> sp, val, VMM_WRITE);
    vm -> sp += 4;
}

void tc_vm_stack_pushuint(struct VM *vm, u32 val) {
    if(vm -> mode == VMA_16) {
        tc_vm_stack_push16(vm, val);
    } else {
        tc_vm_stack_push32(vm, val);
    }
}

u8 tc_vm_stack_pop8(struct VM *vm) {
    vm -> sp--;
    return tc_vm_mem_read8(vm, vm -> sp, VMM_READ);
}

u16 tc_vm_stack_pop16(struct VM *vm) {
    vm -> sp -= 2;
    return tc_vm_mem_read16(vm, vm -> sp, VMM_READ);
}

u32 tc_vm_stack_pop32(struct VM *vm) {
    vm -> sp -= 4;
    return tc_vm_mem_read32(vm, vm -> sp, VMM_READ);
}

u32 tc_vm_stack_popuint(struct VM *vm) {
    if(vm -> mode == VMA_16) {
        return tc_vm_stack_pop16(vm);
    }
    return tc_vm_stack_pop32(vm);
}

u32 tc_vm_reg_read(struct VM *vm, u8 id) {
    return vm -> regs[id & 0xf];
}

void tc_vm_reg_write(struct VM *vm, u8 id, u32 val) {
    vm -> regs[id & 0xf] = val;
#ifdef DEBUG
    printf("reg_write %d: %u\n", (int) id, val);
#endif
}

void tc_vm_do_hypercall(struct VM *vm, u8 id) {
    hypercall_tick_fn fn = vm -> ctx -> hypercalls[id];
    if(!fn) {
        vm -> error = VME_INVALID_HYPERCALL;
#ifdef DEBUG
        printf("Error: Invalid hypercall: %d\n", (int) id);
#endif
        return;
    }

    vm -> hypercall_tick = fn;
}

void tc_vm_hypercall_tick(struct VM *vm) {
    u8 ret = vm -> hypercall_tick(vm); // vm -> hypercall_tick is assumed not to be null.
    if(ret) {
#ifdef DEBUG
        if(vm -> hypercall_state) {
            printf("Warning: hypercall_state not null. Possible memory leak.\n");
        }
#endif
        vm -> hypercall_tick = NULL;
        vm -> hypercall_state = NULL;
    }
}

u8 tc_vm_execute_once(struct VM *vm) {
    u32 a, b, c;

    if(vm -> hypercall_tick) {
        tc_vm_hypercall_tick(vm);
        return 0;
    }

    u8 ins = tc_vm_iread8(vm);
    if(vm -> error) {
        return 1;
    }

    switch(ins) {
        case VMI_NOP:
            break;
        
        case VMI_MOV:
            a = tc_vm_iread8(vm); // target
            b = tc_vm_iread8(vm); // source
            tc_vm_reg_write(vm, a, tc_vm_reg_read(vm, b));
            break;
        
        case VMI_LOAD:
            a = tc_vm_iread8(vm); // register id
            b = tc_vm_ireaduint(vm); // mem address
            tc_vm_reg_write(vm, a, tc_vm_mem_readuint(vm, b, 0));
            break;
        
        case VMI_STORE:
            a = tc_vm_iread8(vm); // register id
            b = tc_vm_ireaduint(vm); // mem address
            tc_vm_mem_writeuint(vm, b, tc_vm_reg_read(vm, a), 0);
            break;
        
        case VMI_ADD:
            a = tc_vm_iread8(vm);
            b = tc_vm_iread8(vm);
            tc_vm_reg_write(vm, 0, tc_vm_reg_read(vm, a) + tc_vm_reg_read(vm, b));
            break;
        
        case VMI_SUB:
            a = tc_vm_iread8(vm);
            b = tc_vm_iread8(vm);
            tc_vm_reg_write(vm, 0, tc_vm_reg_read(vm, a) - tc_vm_reg_read(vm, b));
            break;
        
        case VMI_MUL:
            a = tc_vm_iread8(vm);
            b = tc_vm_iread8(vm);
            tc_vm_reg_write(vm, 0, tc_vm_reg_read(vm, a) * tc_vm_reg_read(vm, b));
            break;
        
        case VMI_DIV:
            a = tc_vm_iread8(vm);
            b = tc_vm_iread8(vm);
            tc_vm_reg_write(vm, 0, tc_vm_reg_read(vm, a) / tc_vm_reg_read(vm, b));
            break;
        
        case VMI_SHL:
            a = tc_vm_iread8(vm);
            b = tc_vm_iread8(vm);
            tc_vm_reg_write(vm, 0, tc_vm_reg_read(vm, a) << tc_vm_reg_read(vm, b));
            break;
        
        case VMI_SHR:
            a = tc_vm_iread8(vm);
            b = tc_vm_iread8(vm);
            tc_vm_reg_write(vm, 0, tc_vm_reg_read(vm, a) >> tc_vm_reg_read(vm, b));
            break;

        case VMI_AND:
            a = tc_vm_iread8(vm);
            b = tc_vm_iread8(vm);
            tc_vm_reg_write(vm, 0, tc_vm_reg_read(vm, a) & tc_vm_reg_read(vm, b));
            break;
        
        case VMI_OR:
            a = tc_vm_iread8(vm);
            b = tc_vm_iread8(vm);
            tc_vm_reg_write(vm, 0, tc_vm_reg_read(vm, a) | tc_vm_reg_read(vm, b));
            break;

        case VMI_XOR:
            a = tc_vm_iread8(vm);
            b = tc_vm_iread8(vm);
            tc_vm_reg_write(vm, 0, tc_vm_reg_read(vm, a) ^ tc_vm_reg_read(vm, b));
            break;
        
        case VMI_GT:
            a = tc_vm_iread8(vm);
            b = tc_vm_iread8(vm);
            tc_vm_reg_write(vm, 0, tc_vm_reg_read(vm, a) > tc_vm_reg_read(vm, b));
            break;
        
        case VMI_LT:
            a = tc_vm_iread8(vm);
            b = tc_vm_iread8(vm);
            tc_vm_reg_write(vm, 0, tc_vm_reg_read(vm, a) < tc_vm_reg_read(vm, b));
            break;
        
        case VMI_EQ:
            a = tc_vm_iread8(vm);
            b = tc_vm_iread8(vm);
            tc_vm_reg_write(vm, 0, tc_vm_reg_read(vm, a) == tc_vm_reg_read(vm, b));
            break;

        case VMI_JMP:
            a = tc_vm_iread8(vm); // register with target address
            vm -> ip = tc_vm_reg_read(vm, a);
            break;
        
        case VMI_CONDJMP:
            a = tc_vm_iread8(vm); // condition
            b = tc_vm_iread8(vm); // register with target address
            if(tc_vm_reg_read(vm, a)) {
                vm -> ip = tc_vm_reg_read(vm, b);
            }
            break;
        
        case VMI_LOADVAL:
            a = tc_vm_iread8(vm); // target
            tc_vm_reg_write(vm, a, tc_vm_ireaduint(vm));
            break;
        
        case VMI_HYPERCALL:
            a = tc_vm_iread8(vm);
            tc_vm_do_hypercall(vm, a);
            break;
        
        case VMI_PUSH:
            a = tc_vm_iread8(vm);
            tc_vm_stack_pushuint(vm, tc_vm_reg_read(vm, a));
            break;
        
        case VMI_PUSH8:
            a = tc_vm_iread8(vm);
            tc_vm_stack_push8(vm, tc_vm_reg_read(vm, a));
            break;
        
        case VMI_PUSH16:
            a = tc_vm_iread8(vm);
            tc_vm_stack_push16(vm, tc_vm_reg_read(vm, a));
            break;
        
        case VMI_PUSH32:
            a = tc_vm_iread8(vm);
            tc_vm_stack_push32(vm, tc_vm_reg_read(vm, a));
            break;
        
        case VMI_POP:
            tc_vm_reg_write(vm, 0, tc_vm_stack_popuint(vm));
            break;
        
        case VMI_POP8:
            tc_vm_reg_write(vm, 0, tc_vm_stack_pop8(vm));
            break;
        
        case VMI_POP16:
            tc_vm_reg_write(vm, 0, tc_vm_stack_pop16(vm));
            break;
        
        case VMI_POP32:
            tc_vm_reg_write(vm, 0, tc_vm_stack_pop32(vm));
            break;
        
        case VMI_ENTER32:
            tc_vm_enter_32(vm);
            break;
        
        case VMI_ENTER16:
            tc_vm_enter_16(vm);
            break;
        
        case VMI_HALT:
            return 1;
        
        case VMI_GPIO_DIGITAL_READ:
            a = tc_vm_iread8(vm); // register with pin
            tc_vm_reg_write(vm, 0, vm -> ctx -> gpio_read ? vm -> ctx -> gpio_read(tc_vm_reg_read(vm, a)) : 0);
            break;
        
        case VMI_GPIO_DIGITAL_WRITE:
            a = tc_vm_iread8(vm); // register with pin
            b = tc_vm_iread8(vm); // register with value
            if(vm -> ctx -> gpio_write) {
                vm -> ctx -> gpio_write(tc_vm_reg_read(vm, a), tc_vm_reg_read(vm, b));
            }
            break;
        
        case VMI_GPIO_SET_PIN_MODE:
            a = tc_vm_iread8(vm); // register with pin
            b = tc_vm_iread8(vm); // register with mode
            if(vm -> ctx -> gpio_set_pin_mode) {
                vm -> ctx -> gpio_set_pin_mode(tc_vm_reg_read(vm, a), tc_vm_reg_read(vm, b));
            }
            break;
        
        default:
            tc_vm_reset(vm);
    }

    return 0;
}

u16 tc_vm_execute(struct VM *vm) {
    while(tc_vm_execute_once(vm) == 0);
    return tc_vm_reg_read(vm, 0);
}

#endif

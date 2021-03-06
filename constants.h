#ifndef _TERMINAL_CONTROL_CONSTANTS_H_
#define _TERMINAL_CONTROL_CONSTANTS_H_

#define CONTROL_GPIO_READ 0x01
#define CONTROL_GPIO_WRTIE 0x02
#define CONTROL_CODE_EXEC 0x03
#define CONTROL_GET_DEVICE_STATUS 0x04
#define CONTROL_RESET_VMS 0x05

#define DATA_GPIO_READ 0x01
#define DATA_CODE_EXEC 0x03
#define DATA_GET_DEVICE_STATUS 0x04
#define DATA_RESET_VMS 0x05

#define VMM_READ 1
#define VMM_WRITE 2
#define VMM_EXEC 4

#define VME_ACCESS_VIOLATION 1
#define VME_INVALID_HYPERCALL 2

#define VMA_16 0
#define VMA_32 1
#define VMA_16_CODE_BEGIN 0
#define VMA_16_CODE_END 16384
#define VMA_16_STACK_BEGIN 16384
#define VMA_16_STACK_END 65536
#define VMA_32_CODE_BEGIN 0x08000000
#define VMA_32_CODE_END 0x10000000
#define VMA_32_STACK_BEGIN 0x20000000
#define VMA_32_STACK_END 0x28000000

#ifndef CYCLES_PER_TICK
#define CYCLES_PER_TICK 128
#endif

#ifndef MAX_VMS
#define MAX_VMS 16
#endif

#ifndef VM_STACK_SIZE
#define VM_STACK_SIZE 128
#endif

#endif

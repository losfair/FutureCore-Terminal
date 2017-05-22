#ifndef _TERMINAL_CONTROL_VM_INSTRUCTIONS_H_
#define _TERMINAL_CONTROL_VM_INSTRUCTIONS_H_

#define VMI_NOP 0x00

#define VMI_MOV 0x01
#define VMI_LOAD 0x02
#define VMI_STORE 0x03
#define VMI_ADD 0x04
#define VMI_SUB 0x05
#define VMI_MUL 0x06
#define VMI_DIV 0x07
#define VMI_SHL 0x08
#define VMI_SHR 0x09
#define VMI_AND 0x0a
#define VMI_OR 0x0b
#define VMI_XOR 0x0c
#define VMI_GT 0x0d
#define VMI_LT 0x0e
#define VMI_EQ 0x0f
#define VMI_JMP 0x10
#define VMI_CONDJMP 0x11
#define VMI_LOADVAL 0x12
#define VMI_HALT 0xff

#define VMI_GPIO_DIGITAL_READ 0x80
#define VMI_GPIO_DIGITAL_WRITE 0x81
#define VMI_GPIO_SET_PIN_MODE 0x82

#endif

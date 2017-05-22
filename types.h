#ifndef _TERMINAL_CONTROL_TYPES_H_
#define _TERMINAL_CONTROL_TYPES_H_

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
//typedef unsigned long size_t;

typedef char * (*malloc_fn)(size_t size);
typedef void (*free_fn)(char *ptr);
typedef void (*gpio_write_fn)(u16 pin, u8 val);
typedef u8 (*gpio_read_fn)(u16 pin);
typedef void (*gpio_set_pin_mode_fn)(u16 pin, u8 mode); // modes: 0 for input, 1 for output
typedef int (*net_write_fn)(void *param, const char *data, size_t len);

#endif

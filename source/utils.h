#ifndef _UTILS_H
#define _UTILS_H

#include "types.h"
#include <ctype.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <unistd.h>
#include <malloc.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <direct.h>
#endif

#ifndef MAX_PATH
#define MAX_PATH 255
#endif

#define BIT(n) (1 << (n))
#define sizeof_member(type, member) sizeof(((type*)NULL)->member)

u32 align(u32 offset, u32 alignment);
u64 align64(u64 offset, u32 alignment);
u64 getle64(const u8* p);
u32 getle32(const u8* p);
u32 getle16(const u8* p);
u64 getbe64(const u8* p);
u32 getbe32(const u8* p);
u32 getbe16(const u8* p);
void putle16(u8* p, u16 n);
void putle32(u8* p, u32 n);
void putle64(u8* p, u64 n);
void putbe16(u8* p, u16 n);
void putbe32(u8* p, u32 n);
void putbe64(u8* p, u64 n);

u32 swap_uint32(u32 val);
void reverse_endian(u32* buffer, size_t size);
void reverse_words(u32* buffer, size_t size);
void reverse(u32* buffer, size_t size);

void memdump(FILE* fout, const char* prefix, const u8* data, u32 size);
void hexdump(void *ptr, int buflen);

int makedir(const char* dir);

bool isnumeric(const char* string);

#endif

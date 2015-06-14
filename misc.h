#ifndef _MISC_H__
#define _MISC_H__

#define PAGE_SIZE 4096

typedef struct
{
	char * data;
	size_t size;
} DATA_ENTRY_t;

#define Error(format,...) fprintf(stderr, "Error: " format "\n", __VA_ARGS__);
#define Warning(format,...) printf("Warning: " format "\n", __VA_ARGS__);
#define OutInfo(format,...) printf(format "\n", __VA_ARGS__);

extern bool verbose;

#endif /* _MISC_H__ */
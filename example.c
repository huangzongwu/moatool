#include "moatool.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum e_mode {MOA_LIST, MOA_SPLIT, MOA_REDUCE} mode;

moa_boolean_t parse_args(int, char**);
void usage(const char*);

int main(int argc, char** argv)
{
	if (!parse_args(argc, argv))
	{
		usage(argv[0]);
		return EXIT_FAILURE;
	}
	
	struct s_mach_file* mach_file = NULL;
	moa_error_t ret;
	
	if ((ret = moa_alloc(&mach_file, argv[2])) != MOA_SUCCESS) // Alloc file
	{
		moa_error(ret);
		exit(EXIT_FAILURE);
	}
	
	if ((ret = moa_read_fat_section(mach_file)) != MOA_SUCCESS)
	{
		moa_error(ret);
		moa_dealloc(&mach_file);
		exit(EXIT_FAILURE);
	}
	
	switch (mode)
	{
		case MOA_LIST:
			printf("[+] %s fat description (%llu bytes)\n", argv[2], mach_file->file_stats.st_size);
			moa_print_fat_section(mach_file);
			break;
		case MOA_SPLIT:
			printf("[+] Splitting %s (%llu bytes)\n", argv[2], mach_file->file_stats.st_size);
			if ((ret = moa_split(mach_file)) != MOA_SUCCESS)
			{
				printf("[+] Couldn't split binary.\n");
				moa_error(ret);
			}
			break;
		case MOA_REDUCE:
			printf("[+] Reducing %s (%llu bytes)\n", argv[2], mach_file->file_stats.st_size);
			if ((ret = moa_reduce(mach_file))  != MOA_SUCCESS)
			{
				printf("[+] Couldn't reduce binary.\n");
				moa_error(ret);
			}
			break;
		default:
			printf("[+] Invalid option : %s\n", argv[1]);
			usage(argv[0]);
	}
	
	moa_dealloc(&mach_file); // dealloc our file !
	
	return EXIT_SUCCESS;
}

void usage(const char* ptr_prog_name)
{
	fprintf(stderr, "\n%s usage :\n\n", ptr_prog_name);
	fprintf(stderr, "\t%s -[lrs] file\n", ptr_prog_name);
	fprintf(stderr, "\t-l : Print the content of universal binaries headers.\n");
	fprintf(stderr, "\t-r : Remove the useless architecture code from the binary.\n");
	fprintf(stderr, "\t-s : Split the universal binary archive in 2 independant binaries.\n");
}

moa_boolean_t parse_args(int argc, char** argv)
{
	if (argc != 3)
		return FALSE;
	
	if (0 == strncmp(argv[1], "-l", strlen(argv[1])))
		mode = MOA_LIST;
	else if (0 == strncmp(argv[1], "-s", strlen(argv[1])))
		mode = MOA_SPLIT;
	else if (0 == strncmp(argv[1], "-r", strlen(argv[1])))
		mode = MOA_REDUCE;
	else
		return FALSE;
	
	return TRUE;
}

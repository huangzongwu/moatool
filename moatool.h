#ifndef _LIB_MOATOOL_H_
#define _LIB_MOATOOL_H_

#include <mach-o/fat.h>
#include <sys/types.h>
#include <sys/stat.h>

typedef unsigned char	byte;
typedef char			moa_boolean_t;
typedef int				moa_error_t;

struct s_fat_section
{
	struct fat_header	fat_header;	/* Fat header */
	struct fat_arch*	fat_archs;	/* Fat archs (fat_header.nfat_arch) */
};

struct s_mach_file
{
	int						fd;				/* File descriptor */
	char*					filename;		/* Filename */
	struct stat				file_stats;		/* File stats */
	struct s_fat_section	fat_section;	/* Fat section */
};

#define TRUE	1
#define FALSE	0

#define MOA_SUCCESS					1	/* All OK */
#define MOA_ERR_FILENAME_ALLOC		-1	/* malloc() failure */
#define MOA_ERR_OPEN_FILE			-2	/* open() failure */
#define MOA_ERR_CREATE_FILE			-3	/* open() failure */
#define MOA_ERR_STAT				-4	/* stat() failure */
#define MOA_ERR_READ_DATA			-5	/* read() failure */
#define MOA_ERR_WRITE_DATA			-6	/* write() failure */
#define MOA_ERR_READ_FAT_HEADER		-7	/* read() failure */
#define MOA_ERR_READ_FAT_ARCH		-8	/* read() failure */
#define MOA_ERR_NOT_MACH_ARCHIVE	-9	/* File is not a mach archive */
#define MOA_ERR_CANNOT_REDUCE		-10	/* File can not be reduced */
#define MOA_ERR_ALLOCATE			-11	/* Could not allocate mach file */
#define MOA_ERR_UNKNOW_ARCH			-12 /* Unknow architecture */
#define MOA_ERR_ALREADY_ALLOC		-13 /* File pointer already allocated */
#define MOA_ERR_NULLPTR				-14 /* NULL mach file pointer */

#define MOA_VERSION	"1.1.0"

moa_error_t		moa_alloc(struct s_mach_file**, const char*);
void			moa_dealloc(struct s_mach_file**);

moa_error_t		moa_read_fat_section(struct s_mach_file*);
moa_error_t		moa_reduce(struct s_mach_file*);
moa_error_t		moa_split(struct s_mach_file*);

moa_boolean_t	moa_is_mach_archive(const struct s_mach_file*);
cpu_type_t		moa_working_arch(void);
cpu_type_t		moa_arch_to_keep_index(const struct s_mach_file*);

void			moa_print_fat_section(struct s_mach_file*);
void			moa_error(const moa_error_t);
const char*		moa_version(void);

#endif /* _LIB_MOATOOL_H_ */

#include "moatool.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <math.h>
#include <sys/uio.h>
#include <errno.h>
#include <architecture/byte_order.h>
#include <mach-o/swap.h>
#include <mach-o/arch.h>

/**
 * \fn moa_error_t moa_alloc(struct s_mach_file** ptr_mach_file, const char* ptr_filename)
 * \brief Allocate a mach file object.
 *
 * \param ptr_mach_file Pointer to mach archive.
 * \param ptr_filename name of the mach file.
 *
 * \return MOA_SUCCESS if file alloc succeed, else error number.
 */
moa_error_t
moa_alloc(struct s_mach_file** ptr_mach_file, const char* filename)
{
	if (NULL == (*ptr_mach_file) && filename != NULL) // mach file pointer is free, we can allocate
	{
		/// Allocate memory for the mach file
		if (NULL == ((*ptr_mach_file) = (struct s_mach_file*)malloc(sizeof(struct s_mach_file))))
			return MOA_ERR_ALLOCATE;
		/// Initialize attributes
		(*ptr_mach_file)->fat_section.fat_archs = NULL;
		/// Copy the filename
		const size_t filename_length = strlen(filename);
		(*ptr_mach_file)->filename = (char*)calloc(filename_length + 1, sizeof(char));
		if (NULL == (*ptr_mach_file)->filename)
		{
			moa_dealloc(ptr_mach_file);
			return MOA_ERR_FILENAME_ALLOC;
		}
		strncpy((*ptr_mach_file)->filename, filename, filename_length);
		/// Open the file
		if (-1 == ((*ptr_mach_file)->fd = open(filename, O_RDONLY)))
		{
			moa_dealloc(ptr_mach_file);
			return MOA_ERR_OPEN_FILE;
		}
		/// Get the file stats
		if (-1 == stat(filename, &(*ptr_mach_file)->file_stats))
		{
			moa_dealloc(ptr_mach_file);
			return MOA_ERR_STAT;
		}
		return MOA_SUCCESS;
	}
	else
		return MOA_ERR_ALREADY_ALLOC;
}

/**
 * \fn void moa_dealloc(struct s_mach_file** ptr_mach_file)
 * \brief Free all the allocated memory and close descriptor.
 *
 * \param ptr_mach_file Pointer to mach archive.
 */
void
moa_dealloc(struct s_mach_file** ptr_mach_file)
{
	if ((*ptr_mach_file) != NULL) // Mach file is allocated
	{
		if ((*ptr_mach_file)->filename != NULL)
			free((*ptr_mach_file)->filename), (*ptr_mach_file)->filename = NULL;
		if ((*ptr_mach_file)->fat_section.fat_archs != NULL)
			free((*ptr_mach_file)->fat_section.fat_archs), (*ptr_mach_file)->fat_section.fat_archs = NULL;
		if ((*ptr_mach_file)->fd != -1)
			close((*ptr_mach_file)->fd), (*ptr_mach_file)->fd = -1;
		free((*ptr_mach_file));
		(*ptr_mach_file) = NULL;
	}
}

/**
 * \fn moa_error_t moa_read_fat_section(struct s_mach_file* ptr_mach_file)
 * \brief Read the fat section of a mach_file (fat_header + fat_arch).
 *
 * \param ptr_mach_file Pointer to mach archive.
 *
 * \return MOA_SUCCESS if all succeed, else error number.
 */
moa_error_t
moa_read_fat_section(struct s_mach_file* ptr_mach_file)
{
	if (NULL == ptr_mach_file)
		return MOA_ERR_NULLPTR;
	/// Reset file offset
	lseek(ptr_mach_file->fd, (off_t)0, SEEK_SET);

	/// Read the fat header
	const size_t mach_header_size = sizeof(ptr_mach_file->fat_section.fat_header);
	if (read(ptr_mach_file->fd, &ptr_mach_file->fat_section.fat_header, mach_header_size) != (ssize_t)mach_header_size)
		return MOA_ERR_READ_FAT_HEADER;

	/// Check if the file is actually a mach archive
	if (!moa_is_mach_archive(ptr_mach_file))
		return MOA_ERR_NOT_MACH_ARCHIVE;

	/// Get host machine byte order
	/// If intel CPU, we need to change the byte order to lil endian
	enum NXByteOrder host_byte_order = NXHostByteOrder();
	if (NX_LittleEndian == host_byte_order)
		swap_fat_header(&ptr_mach_file->fat_section.fat_header, NX_LittleEndian);
	else if (NX_UnknownByteOrder == NXHostByteOrder())
		return MOA_ERR_UNKNOW_ARCH;

	/// Read the N fat archs
	if (ptr_mach_file->fat_section.fat_archs != NULL) // Avoid memory leaks ;)
		free(ptr_mach_file->fat_section.fat_archs);

	const size_t fat_arch_size = ptr_mach_file->fat_section.fat_header.nfat_arch * sizeof(*ptr_mach_file->fat_section.fat_archs);
	if (NULL == (ptr_mach_file->fat_section.fat_archs = (struct fat_arch*)malloc(fat_arch_size)))
		return MOA_ERR_READ_FAT_ARCH;

	if (read(ptr_mach_file->fd, ptr_mach_file->fat_section.fat_archs, fat_arch_size) != (ssize_t)fat_arch_size)
		return MOA_ERR_READ_FAT_ARCH;

	if (NX_LittleEndian == host_byte_order)
		swap_fat_arch(ptr_mach_file->fat_section.fat_archs, ptr_mach_file->fat_section.fat_header.nfat_arch, NX_LittleEndian);
	return MOA_SUCCESS;
}

/**
 * \fn moa_error_t moa_reduce(struct s_mach_file* ptr_mach_file)
 * \brief Reduce the given mach archive by removing the useless code.
 *
 * \param ptr_mach_file Pointer to mach archive.
 *
 * \return MOA_SUCCESS if reduce succeed, else error number.
 */
moa_error_t
moa_reduce(struct s_mach_file* ptr_mach_file)
{
	if (NULL == ptr_mach_file)
		return MOA_ERR_NULLPTR;
	/// Get the index of the arch to keep in the fat arch
	const cpu_type_t arch_to_keep_index = moa_arch_to_keep_index(ptr_mach_file);
	if (-1 == arch_to_keep_index) // Unknow arch
		return MOA_ERR_CANNOT_REDUCE;

	/// Create the name of the temporary file to hold the remaining arch
	const size_t length = strlen(ptr_mach_file->filename);
	char* ptr_new_filename = (char*)calloc(length + 2, sizeof(char)); // Name of the new file
	if (NULL == ptr_new_filename)
		return MOA_ERR_FILENAME_ALLOC;
	strncpy(ptr_new_filename, ptr_mach_file->filename, length);
	strcat(ptr_new_filename, "1");

	/// Create the new file
	int fd_out = open(ptr_new_filename, O_CREAT | O_WRONLY | O_TRUNC, S_IRWXU);
	if (-1 == fd_out)
	{
		free(ptr_new_filename);
		return MOA_ERR_CREATE_FILE;
	}
	/// Jump to the offset who contains the arch we want
	lseek(ptr_mach_file->fd, (off_t)ptr_mach_file->fat_section.fat_archs[arch_to_keep_index].offset, SEEK_SET);

	/// Get the optimal buffer size and allocate
	const blksize_t best_buf_size = ptr_mach_file->file_stats.st_blksize;
	byte* buffer = (byte*)calloc((size_t)best_buf_size, sizeof(byte));

	/// Copy the good arch
	ssize_t bytes_read = 0;
	uint32_t new_file_size = ptr_mach_file->fat_section.fat_archs[arch_to_keep_index].size;
	uint32_t bytes_written = 0;
	while (bytes_written < new_file_size)
	{
		const uint32_t bytes_remaining = new_file_size - bytes_written; // Number of bytes remaining to write
		bytes_read = (bytes_remaining < (uint32_t)best_buf_size) ? read(ptr_mach_file->fd, buffer, (size_t)bytes_remaining) : read(ptr_mach_file->fd, buffer, (size_t)best_buf_size);
		if (-1 == bytes_read)
		{
			close(fd_out);
			free(buffer);
			free(ptr_new_filename);
			return MOA_ERR_READ_DATA;
		}
		if (-1 == write(fd_out, buffer, (size_t)bytes_read))
		{
			close(fd_out);
			free(buffer);
			free(ptr_new_filename);
			return MOA_ERR_WRITE_DATA;
		}
		bytes_written += (uint32_t)bytes_read;
	}
	close(fd_out);
	/// delete the old file
	unlink(ptr_mach_file->filename);
	/// Rename the temporary with the name of the original
	rename(ptr_new_filename, ptr_mach_file->filename);
	free(buffer);
	free(ptr_new_filename);

	return MOA_SUCCESS;
}

/**
 * \fn moa_error_t moa_split(struct s_mach_file* ptr_mach_file)
 * \brief Split the given mach archive in nfat_arch single binaries.
 *
 * \param ptr_mach_file Pointer to mach archive.
 *
 * \return MOA_SUCCESS if split succeed, else error number.
 */
moa_error_t
moa_split(struct s_mach_file* ptr_mach_file)
{
	if (NULL == ptr_mach_file)
		return MOA_ERR_NULLPTR;
	ushort un;
	for (un = 0; un < ptr_mach_file->fat_section.fat_header.nfat_arch; un++)
	{
		/// Create the filename for the arch
		const size_t length = strlen(ptr_mach_file->filename);
		char* new_filename = (char*)calloc(length + 8, sizeof(char));
		if (NULL == new_filename)
			return MOA_ERR_FILENAME_ALLOC;
		strncpy(new_filename, ptr_mach_file->filename, length);
		switch (ptr_mach_file->fat_section.fat_archs[un].cputype)
		{
			case CPU_TYPE_X86:
				strncat(new_filename, "_X86", (size_t)7);
				break;
			case CPU_TYPE_X86_64:
				strncat(new_filename, "_X86_64", (size_t)7);
				break;
			case CPU_TYPE_POWERPC:
				strncat(new_filename, "_PPC", (size_t)7);
				break;
			case CPU_TYPE_POWERPC64:
				strncat(new_filename, "_PPC_64", (size_t)7);
				break;
			default:
				strncat(new_filename, "_UNKNOW", (size_t)7);
		}
		printf("Creating %s (%u bytes)... ", new_filename, ptr_mach_file->fat_section.fat_archs[un].size);

		/// Create the file
		int fd_out = open(new_filename, O_CREAT | O_WRONLY | O_TRUNC, S_IRWXU);
		if (-1 == fd_out)
		{
			printf("failed.\n");
			free(new_filename);
			return MOA_ERR_CREATE_FILE;
		}

		/// Jump to the offset who contains the arch
		lseek(ptr_mach_file->fd, (off_t)ptr_mach_file->fat_section.fat_archs[un].offset, SEEK_SET);

		/// Get the optimal buffer size and allocate
		const blksize_t best_buf_size = ptr_mach_file->file_stats.st_blksize;
		byte* buffer = (byte*)calloc((size_t)best_buf_size, sizeof(byte));

		/// Copy the arch
		ssize_t bytes_read = 0;
		uint32_t new_file_size = ptr_mach_file->fat_section.fat_archs[un].size;
		uint32_t bytes_written = 0;
		while (bytes_written < new_file_size)
		{
			const uint32_t bytes_remaining = new_file_size - bytes_written;
			bytes_read = (bytes_remaining < (uint32_t)best_buf_size) ? read(ptr_mach_file->fd, buffer, (size_t)bytes_remaining) : read(ptr_mach_file->fd, buffer, (size_t)best_buf_size);
			if (-1 == bytes_read)
			{
				printf("failed.\n");
				close(fd_out);
				free(buffer);
				free(new_filename);
				return MOA_ERR_READ_DATA;
			}
			if (-1 == write(fd_out, buffer, (size_t)bytes_read))
			{
				printf("failed.\n");
				close(fd_out);
				free(buffer);
				free(new_filename);
				return MOA_ERR_WRITE_DATA;
			}
			bytes_written += (uint32_t)bytes_read;
		}
		close(fd_out);
		printf("done.\n");
		free(buffer);
		free(new_filename);
	}
	return MOA_SUCCESS;
}

/**
 * \fn moa_boolean_t moa_is_mach_archive(const struct s_mach_file* ptr_mach_file)
 * \brief Check if the mach file is an archive.
 *
 * \param ptr_mach_file Pointer to mach archive.
 *
 * \return TRUE if the mach file is an archive, else FALSE.
 */
moa_boolean_t
moa_is_mach_archive(const struct s_mach_file* ptr_mach_file)
{
	if (NULL == ptr_mach_file)
		return FALSE;
	const uint32_t magic = ptr_mach_file->fat_section.fat_header.magic;
	return (FAT_MAGIC == magic || FAT_CIGAM == magic);
}

/**
 * \fn cpu_type_t moa_working_arch(void)
 * \brief Returns the arch of the computer.
 *
 * \return Constant associated to the arch of the computer.
 */
cpu_type_t
moa_working_arch(void)
{
	const NXArchInfo* arch_info = NXGetLocalArchInfo();
	if (NULL == arch_info)
		return CPU_TYPE_ANY;
	return arch_info->cputype;
}

/**
 * \fn cpu_type_t moa_arch_to_keep_index(const struct s_mach_file* ptr_mach_file)
 * \brief Returns the index of the arch to keep in the mach file.
 *
 * \param ptr_mach_file Pointer to mach archive.
 *
 * \return Index of the arch to keep in the struct or -1 if nothing can be done.
 */
cpu_type_t
moa_arch_to_keep_index(const struct s_mach_file* ptr_mach_file)
{
	const cpu_type_t working_arch = moa_working_arch();
	if (CPU_TYPE_ANY == working_arch || NULL == ptr_mach_file)
		return -1;
	ushort un;
	for (un = 0; un < ptr_mach_file->fat_section.fat_header.nfat_arch; un++)
		if (working_arch == ptr_mach_file->fat_section.fat_archs[un].cputype)
			return un;
	return -1;
}

/**
 * \fn void moa_print_fat_section(struct s_mach_file* ptr_mach_file)
 * \brief Prints the fat section of a mach archive (fat_header + fat_arch).
 *
 * \param ptr_mach_file Pointer to mach archive.
 */
void
moa_print_fat_section(struct s_mach_file* ptr_mach_file)
{
	if (NULL == ptr_mach_file)
		return;
	printf("fat_header :\n");
	printf("--------------------------\n");
	printf("| fat_magic : 0x%x |\n", ptr_mach_file->fat_section.fat_header.magic);
	printf("| nfat_arch : %u          |\n", ptr_mach_file->fat_section.fat_header.nfat_arch);
	printf("--------------------------\n\n");
	
	if (ptr_mach_file->fat_section.fat_archs != NULL)
	{
		ushort un;
		for (un = 0; un < ptr_mach_file->fat_section.fat_header.nfat_arch; un++)
		{
			printf("Arch %hu :\n", un);
			printf("---------------------------\n");
			printf("| cputype    : ");
			switch (ptr_mach_file->fat_section.fat_archs[un].cputype)
			{
				case CPU_TYPE_X86:
					printf("CPU_TYPE_X86 (%u)\n", ptr_mach_file->fat_section.fat_archs[un].cputype);
					break;
				case CPU_TYPE_X86_64:
					printf("CPU_TYPE_X86_64 (%u)\n", ptr_mach_file->fat_section.fat_archs[un].cputype);
					break;
				case CPU_TYPE_POWERPC:
					printf("CPU_TYPE_POWERPC (%u)\n", ptr_mach_file->fat_section.fat_archs[un].cputype);
					break;
				case CPU_TYPE_POWERPC64:
					printf("CPU_TYPE_POWERPC64 (%u)\n", ptr_mach_file->fat_section.fat_archs[un].cputype);
					break;
				default:
					printf("CPU_TYPE_ANY (%u)\n", ptr_mach_file->fat_section.fat_archs[un].cputype);
			}
			printf("| cpusubtype : %u\n", ptr_mach_file->fat_section.fat_archs[un].cpusubtype);
			printf("| offset     : %u\n", ptr_mach_file->fat_section.fat_archs[un].offset);
			printf("| size       : %u\n", ptr_mach_file->fat_section.fat_archs[un].size);
			printf("| align      : %u\n", (unsigned)pow(2.0, (double)ptr_mach_file->fat_section.fat_archs[un].align));
			printf("---------------------------\n\n");
		}
	}
}

/**
 * \fn void moa_error(const moa_error_t error_code)
 * \brief Prints the error string associated to the error number.
 *
 * \param error_code Error number.
 */
void
moa_error(const moa_error_t error_code)
{
	switch (error_code)
	{
		case MOA_SUCCESS:
			fprintf(stderr, "No error.\n");
			break;
		case MOA_ERR_FILENAME_ALLOC:
			fprintf(stderr, "malloc() failed.\n");
			break;
		case MOA_ERR_OPEN_FILE:
			fprintf(stderr, "Error when opening file.\nopen() failed --> %s.\n", strerror(errno));
			break;
		case MOA_ERR_CREATE_FILE:
			fprintf(stderr, "Error when creating file\nopen() failed --> %s.\n", strerror(errno));
			break;
		case MOA_ERR_STAT:
			fprintf(stderr, "Error when getting file information\nstat() failed --> %s.\n", strerror(errno));
			break;
		case MOA_ERR_READ_DATA:
			fprintf(stderr, "Error when reading file\nread() failed --> %s.\n", strerror(errno));
			break;
		case MOA_ERR_WRITE_DATA:
			fprintf(stderr, "Error when writing into file\nwrite() failed --> %s.\n", strerror(errno));
			break;
		case MOA_ERR_READ_FAT_HEADER:
			fprintf(stderr, "Error when reading fat_header\nread() failed --> %s.\n", strerror(errno));
			break;
		case MOA_ERR_READ_FAT_ARCH:
			fprintf(stderr, "Error when reading fat_arch\nread() failed --> %s.\n", strerror(errno));
			break;
		case MOA_ERR_NOT_MACH_ARCHIVE:
			fprintf(stderr, "This file is not a mach archive.\n");
			break;
		case MOA_ERR_CANNOT_REDUCE:
			fprintf(stderr, "The file can't be reduced.\n");
			break;
		case MOA_ERR_UNKNOW_ARCH:
			fprintf(stderr, "You are running on unknow architecture.\n");
			break;
		case MOA_ERR_ALREADY_ALLOC:
			fprintf(stderr, "File pointer already alocated.\n");
			break;
		default:
			fprintf(stderr, "Unknow error.\n");
	}
}

/**
 * \fn const char* moa_version(void)
 * \brief Returns the version number of the library.
 *
 * \return Version number of the library
 */
const char*
moa_version(void)
{
	return MOA_VERSION;
}

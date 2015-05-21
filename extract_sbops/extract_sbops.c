/*
 * extract_sbops - a sandbox operation names extractor for iOS and OS X
 * Copyright (C) 2015 Stefan Esser / SektionEins GmbH <stefan@sektioneins.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <mach-o/loader.h>

struct loaded_macho {
	uint8_t * data;
	uint64_t  datasize;
	boolean_t is64;
	uint8_t * base;
};

void destroy_loaded_file(struct loaded_macho * lf)
{
	if (lf) {
		if (lf->data) {
			free(lf->data);
		}
		memset(lf, 0, sizeof(*lf));
	}
}

#define LOAD_MACHO_SUCCESS 0
#define LOAD_MACHO_ERROR   1

#define LOAD_MACHO_ERROR_NONE                  0
#define LOAD_MACHO_ERROR_ILLEGAL_ARGS          1
#define LOAD_MACHO_ERROR_FOPEN                 2
#define LOAD_MACHO_ERROR_HEADER_READ           3
#define LOAD_MACHO_ERROR_NOT_MACHO             4
#define LOAD_MACHO_ERROR_HEADER_TOOLONG        5
#define LOAD_MACHO_ERROR_ILLEGAL_LOAD_COMMAND  6
#define LOAD_MACHO_ERROR_MACHO_NOSEGMENTS      7
#define LOAD_MACHO_ERROR_MACHO_TOOBIG          8
#define LOAD_MACHO_ERROR_SEGMENT_READ          9

int load_macho_into_memory(char *filename, struct loaded_macho * lf, int * ec)
{
	char header[4096];
	struct mach_header *mh = (struct mach_header *) &header;
	struct mach_header_64 *mh64 = (struct mach_header_64 *) &header;
	struct load_command *lc = NULL;
	uint8_t * end_lc = NULL;
	uint8_t * start_lc = NULL;
	uint8_t * data = NULL;
	uint64_t datasize = 0;
	FILE *f = NULL;
	int i;
	uint64_t lowest_vmaddr = 0xFFFFFFFFFFFFFFFF;
	uint64_t highest_vmaddr = 0x0;
	boolean_t is64 = 0;
	
	/* sanitize input */
	if ((lf == NULL) || (filename == NULL)) {
		*ec = LOAD_MACHO_ERROR_ILLEGAL_ARGS;
		goto error;
	}
	memset(lf, 0, sizeof(*lf));
	*ec = LOAD_MACHO_ERROR_NONE;
	
	f = fopen(filename, "rb");
	if (!f) {
		*ec = LOAD_MACHO_ERROR_FOPEN;
		goto error;
	}
	
	/* once open we can now parse the mach-o header 
	   we only support headers up to 4kb, because  
	   most real files will not have longer headers */
	
	if (fread(&header, 1, sizeof(header), f) != sizeof(header)) {
		fclose(f);
		*ec = LOAD_MACHO_ERROR_HEADER_READ;
		goto error;
	}
	
	/* now check the header */
	
	if (mh->magic == MH_MAGIC) {
		/* need to validate length */
		if (mh->sizeofcmds > sizeof(header)-sizeof(struct mach_header)) {
			*ec = LOAD_MACHO_ERROR_HEADER_TOOLONG;
			goto error;
		}
		
		lc = (struct load_command *) &mh[1];
		start_lc = (uint8_t *) lc;
		end_lc = (uint8_t *) lc + mh->sizeofcmds;
		is64 = 0;
		
	} else if (mh64->magic == MH_MAGIC_64) {
		/* need to validate length */
		if (mh64->sizeofcmds > sizeof(header)-sizeof(struct mach_header_64)) {
			*ec = LOAD_MACHO_ERROR_HEADER_TOOLONG;
			goto error;
		}
		
		lc = (struct load_command *) &mh64[1];
		start_lc = (uint8_t *) lc;
		end_lc = (uint8_t *) lc + mh64->sizeofcmds;
		is64 = 1;
		
	} else {
		*ec = LOAD_MACHO_ERROR_NOT_MACHO;
		goto error;
	}
	
	/* we use mh - cause mh64 starts with same info */
	for (i=0; i<mh->ncmds; i++) {
		
		/* validate that load commands are still in bounds */
		if (((uint8_t *)lc < start_lc) || ((uint8_t *)lc > end_lc)) {
			*ec = LOAD_MACHO_ERROR_ILLEGAL_LOAD_COMMAND;
			goto error;
		}
		
		switch (lc->cmd) {
			case LC_SEGMENT_64:
			{
				struct segment_command_64 * seg64 = (struct segment_command_64 *) lc;
				if (seg64->vmaddr < lowest_vmaddr) {
					lowest_vmaddr = seg64->vmaddr;
				}
				if (seg64->vmaddr + seg64->vmsize > highest_vmaddr) {
					highest_vmaddr = seg64->vmaddr + seg64->vmsize;
				}
			}
			break;
			case LC_SEGMENT:
			{
				struct segment_command * seg = (struct segment_command *) lc;
				if (seg->vmaddr < lowest_vmaddr) {
					lowest_vmaddr = seg->vmaddr;
				}
				if (seg->vmaddr + seg->vmsize > highest_vmaddr) {
					highest_vmaddr = seg->vmaddr + seg->vmsize;
				}
			}
			break;			
		}
		
		lc = (struct load_command *) ((uint8_t *)lc + lc->cmdsize);
		
	}
	
	/* error out if there are no segments in the file */
	if (highest_vmaddr == 0) {
		*ec = LOAD_MACHO_ERROR_MACHO_NOSEGMENTS;
		goto error;
	}
	
	/* error out if the segments span a too big memory area */
	if (highest_vmaddr-lowest_vmaddr > 100*1024*1024) {
		*ec = LOAD_MACHO_ERROR_MACHO_TOOBIG;
		goto error;
	}
	
	/* allocate memory */
	datasize = highest_vmaddr-lowest_vmaddr;
	data = (uint8_t *) malloc(datasize);
	memset(data, 0, datasize);
	memcpy(data, &header, sizeof(header));
	
	/* now load all the segments into memory */
	lc = (struct load_command *) start_lc;
	
	for (i=0; i<mh->ncmds; i++) {
		
		switch (lc->cmd) {
			case LC_SEGMENT_64:
			{
				struct segment_command_64 * seg64 = (struct segment_command_64 *) lc;
				uint64_t segsize = seg64->filesize < seg64->vmsize ? seg64->filesize : seg64->vmsize;
				
				fseek(f, seg64->fileoff, SEEK_SET);
				if (fread(data + seg64->vmaddr - lowest_vmaddr, 1, segsize, f) != segsize) {
					*ec = LOAD_MACHO_ERROR_SEGMENT_READ;
					goto error;
				}
			}
			break;
			case LC_SEGMENT:
			{
				struct segment_command * seg = (struct segment_command *) lc;
				uint64_t segsize = seg->filesize < seg->vmsize ? seg->filesize : seg->vmsize;
				
				fseek(f, seg->fileoff, SEEK_SET);
				if (fread(data + seg->vmaddr - lowest_vmaddr, 1, segsize, f) != segsize) {
					*ec = LOAD_MACHO_ERROR_SEGMENT_READ;
					goto error;
				}
			}
			break;			
		}
		
		lc = (struct load_command *) ((uint8_t *)lc + lc->cmdsize);
		
	}	
	
	/* return values */
	lf->data = data;
	lf->datasize = datasize;
	lf->is64 = is64;
	lf->base = (uint8_t *)lowest_vmaddr;
	
	fclose(f);
	
	return LOAD_MACHO_SUCCESS;
error:
	if (data) {
		free(data);
	}
	if (f) {
		fclose(f);
	}
	return LOAD_MACHO_ERROR;
}

uint8_t * find_sandbox_driver(struct loaded_macho * lf)
{
	char pattern[] = { "com.apple.security.sandbox\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00" };
	uint8_t * pos = NULL;
	uint8_t * start = lf->data;
	uint64_t length = lf->datasize;
	uint8_t * cur = start;
	uint8_t * t = NULL;
	uintptr_t ptrval = 0;
	struct mach_header *mh = NULL;
	
	/* scan for the pattern in memory */
	while (1) {
		/* we search for the string "com.apple.security.sandbox" */
		pos = memmem(cur, length-(cur-start), &pattern, sizeof(pattern)-1);
		
		/* advance the pointer */
		cur = pos + 1;
		
		/* did we find a hit? */
		if (!pos) {
			return NULL;
		}
		
		/* next character should be a digit */
		if (isdigit(pos[64])) {
			break;
		}
	}
	
	/* at this point we should have found the kmod_info */
	/* time to scan back and find the start of the driver */
	
	ptrval = (uintptr_t) (pos - start);
	ptrval &= ~0xfff;
	pos = ptrval + start;
	
	while (pos >= start) {
		mh = (struct mach_header *) pos;
		pos -= 4096;
		
		if ((mh->magic == MH_MAGIC) || (mh->magic == MH_MAGIC_64)) {
			return (uint8_t *) mh;
		}
	}
	
	return NULL;
}

uint8_t * find_opnames_table(struct loaded_macho * lf, uint8_t * sandbox_driver)
{
	char pattern[] = { "default" };
	uint8_t * pos = NULL;
	uint8_t * start = sandbox_driver;
	uint64_t length = lf->datasize - (sandbox_driver - lf->data);
	uint8_t * cur = start;
	uint64_t ptr = 0;
	int sizeofptr = lf->is64 ? 8 : 4;
		
	/* scan for the pattern in memory */
	while (1) {
		/* we search for the string "default" */
		pos = memmem(cur, length-(cur-start), &pattern, sizeof(pattern));
		
		/* did we find a hit? */
		if (!pos) {
			return NULL;
		}
		
		/* otherwise take first hit */
		break;
	}
	
	/* now we need to find a pointer to that string */
	ptr = (uint64_t) lf->base + (pos - lf->data);
	cur = start;
	
	
	pos = memmem(cur, length-(cur-start), &ptr, sizeofptr);
	
	/* can we find that pointer? */
	if (!pos) {
		return NULL;
	}
	
	return pos;
}

void dump_opnames_table(struct loaded_macho * lf, uint8_t * opname_table)
{
	char * default_operation;
	char * current;
	int i = 0;
	uint32_t * opnames32 = (uint32_t *) opname_table;
	uint64_t * opnames64 = (uint64_t *) opname_table;
	
	if (lf->is64) {
		default_operation = (char *)lf->data + opnames64[0] - (uint64_t) lf->base;
		current = (char *)lf->data + opnames64[++i] - (uint64_t) lf->base;
		printf("%s\n", default_operation);
		while (opnames64[i] && current != default_operation) {
			printf("%s\n", current);
			current = (char *)lf->data + opnames64[++i] - (uint64_t) lf->base;
		}
		
	} else {
		default_operation = (char *)lf->data + opnames32[0] - (uint32_t) lf->base;
		current = (char *)lf->data + opnames32[++i] - (uint32_t) lf->base;
		printf("%s\n", default_operation);
		while (opnames32[i] && current != default_operation) {
			printf("%s\n", current);
			current = (char *)lf->data + opnames32[++i] - (uint32_t) lf->base;
		}		
	}
}

int main(int argc, char **argv)
{
	struct loaded_macho lf;
	int error;
	uint8_t * sandbox_driver;
	uint8_t * opname_table;
	
	if (argc != 2) {
		fprintf(stderr, "extract_sbops - a sandbox operation names extractor for iOS and OS X\n");
		fprintf(stderr, "Copyright (C) 2015 Stefan Esser / SektionEins GmbH <stefan@sektioneins.de>\n\n");
		fprintf(stderr, "Usage: %s [kernel/Sandbox] \n\n", argv[0]);
		fprintf(stderr, "   kernel     file containing a decrypted/dumped iOS kernel\n");
		fprintf(stderr, "   Sandbox    file containing the OS X Sandbox kernel extension\n\n");
		_exit(0);
	}
	
	if (load_macho_into_memory(argv[1], &lf, &error) != LOAD_MACHO_SUCCESS) {
		fprintf(stderr, "[-] error: cannot load kernel/Sandbox driver - error code %d\n", error);
		goto error;
	}
	
	sandbox_driver = find_sandbox_driver(&lf);
	
	if (!sandbox_driver) {
		fprintf(stderr, "[-] error: cannot find Sandbox driver in file.");
		goto error;
	}
	
	opname_table = find_opnames_table(&lf, sandbox_driver);
	
	if (!opname_table) {
		fprintf(stderr, "[-] error: cannot find operation_names in Sandbox driver.");
		goto error;		
	}
	dump_opnames_table(&lf, opname_table);
	destroy_loaded_file(&lf);
	return 0;
error:
	destroy_loaded_file(&lf);
	_exit(1);
}
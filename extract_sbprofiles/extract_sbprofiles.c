/*
 * extract_sbprofiles - a sandboxd built-in binary profiles extractor for iOS and OS X
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

/* TODO: 32bit case in macho loader */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <mach-o/loader.h>

int silent = 0;

struct loaded_macho {
	uint8_t * data;
	uint64_t  datasize;
	boolean_t is64;
	uint64_t  base;
	uint64_t  __DATA__const;
	uint64_t  __DATA__constsize;
	uint64_t  __TEXT__cstring;
	uint64_t  __TEXT__cstringsize;
	uint64_t  __DATA__data;
	uint64_t  __DATA__datasize;	
};

inline int is_DATA_const(struct loaded_macho *lf, uint64_t addr)
{
	return (addr >= lf->__DATA__const) && (addr <= lf->__DATA__const + lf->__DATA__constsize);
}

inline int is_TEXT_cstring(struct loaded_macho *lf, uint64_t addr)
{
	return (addr >= lf->__TEXT__cstring) && (addr <= lf->__TEXT__cstring + lf->__TEXT__cstringsize);
}

inline int is_DATA_data(struct loaded_macho *lf, uint64_t addr)
{
	return (addr >= lf->__DATA__data) && (addr <= lf->__DATA__data + lf->__DATA__datasize);
}

inline uint8_t * vmaddr_to_data(struct loaded_macho *lf, uint64_t vmaddr)
{
	return (lf->data + vmaddr - lf->base);
}

inline int is_valid_data(struct loaded_macho * lf, uint64_t vmaddr, uint64_t size)
{
	return (size < 100*1024*1024) && (vmaddr >= lf->base) && (vmaddr + size < lf->base + lf->datasize);
}

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
#define LOAD_MACHO_ERROR_ILLEGAL_SECTION_COUNT 10
#define LOAD_MACHO_ERROR_UNEXPECTED_LAYOUT     11

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
				
				if (strcmp(seg64->segname, "__PAGEZERO") == 0) break;
				
				if (seg64->vmaddr < lowest_vmaddr) {
					lowest_vmaddr = seg64->vmaddr;
				}
				if (seg64->vmaddr + seg64->vmsize > highest_vmaddr) {
					highest_vmaddr = seg64->vmaddr + seg64->vmsize;
				}
				if ((sizeof(struct section_64) * seg64->nsects + sizeof(struct segment_command_64)) > seg64->cmdsize) {
					*ec = LOAD_MACHO_ERROR_ILLEGAL_SECTION_COUNT;
					goto error;
				}
				if (seg64->nsects > 1000) {
					*ec = LOAD_MACHO_ERROR_ILLEGAL_SECTION_COUNT;
					goto error;
				}
			}
			break;
			case LC_SEGMENT:
			{
				struct segment_command * seg = (struct segment_command *) lc;
				
				if (strcmp(seg->segname, "__PAGEZERO") == 0) break;
				
				if (seg->vmaddr < lowest_vmaddr) {
					lowest_vmaddr = seg->vmaddr;
				}
				if (seg->vmaddr + seg->vmsize > highest_vmaddr) {
					highest_vmaddr = seg->vmaddr + seg->vmsize;
				}
				if ((sizeof(struct section) * seg->nsects + sizeof(struct segment_command)) > seg->cmdsize) {
					*ec = LOAD_MACHO_ERROR_ILLEGAL_SECTION_COUNT;
					goto error;
				}
				if (seg->nsects > 1000) {
					*ec = LOAD_MACHO_ERROR_ILLEGAL_SECTION_COUNT;
					goto error;
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
				int i;
				
				fseek(f, seg64->fileoff, SEEK_SET);
				if (fread(data + seg64->vmaddr - lowest_vmaddr, 1, segsize, f) != segsize) {
					*ec = LOAD_MACHO_ERROR_SEGMENT_READ;
					goto error;
				}
				
				for (i=0; i<seg64->nsects; i++) {
					struct section_64 * sec64 = &((struct section_64 *) &seg64[1])[i];
					
					if (strcmp(sec64->segname, "__DATA") == 0) {
						if (strcmp(sec64->sectname, "__data") == 0) {
							lf->__DATA__data = sec64->addr;
							lf->__DATA__datasize = sec64->size;
						} else if (strcmp(sec64->sectname, "__const") == 0) {
							lf->__DATA__const = sec64->addr;
							lf->__DATA__constsize = sec64->size;
						}
					} else if (strcmp(sec64->segname, "__TEXT") == 0) {
						if (strcmp(sec64->sectname, "__cstring") == 0) {
							lf->__TEXT__cstring = sec64->addr;
							lf->__TEXT__cstringsize = sec64->size;
						}
					}
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
				
				for (i=0; i<seg->nsects; i++) {
					struct section * sec = &((struct section *) &seg[1])[i];
					
					if (strcmp(sec->segname, "__DATA") == 0) {
						if (strcmp(sec->sectname, "__data") == 0) {
							lf->__DATA__data = sec->addr;
							lf->__DATA__datasize = sec->size;
						} else if (strcmp(sec->sectname, "__const") == 0) {
							lf->__DATA__const = sec->addr;
							lf->__DATA__constsize = sec->size;
						}
					} else if (strcmp(sec->segname, "__TEXT") == 0) {
						if (strcmp(sec->sectname, "__cstring") == 0) {
							lf->__TEXT__cstring = sec->addr;
							lf->__TEXT__cstringsize = sec->size;
						}
					}
				}
			}
			break;			
		}
		
		lc = (struct load_command *) ((uint8_t *)lc + lc->cmdsize);
		
	}
	
	if ((lf->__DATA__data == 0) || (lf->__DATA__const == 0) || (lf->__TEXT__cstring == 0)) {
		*ec = LOAD_MACHO_ERROR_UNEXPECTED_LAYOUT;
		goto error;
	}
	
	/* return values */
	lf->data = data;
	lf->datasize = datasize;
	lf->is64 = is64;
	lf->base = lowest_vmaddr;
	
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

uint8_t * find_profile_nametable(struct loaded_macho * lf, int * profile_count)
{
	/* we scan the __DATA::__const section for a 
	   list of pointers to __TEXT::__cstring */
	int cnt = 0;
	
	if (lf->is64) {
		uint64_t * start = (uint64_t *) vmaddr_to_data(lf, lf->__DATA__const);
		uint64_t * end   = (uint64_t *) vmaddr_to_data(lf, lf->__DATA__const + lf->__DATA__constsize);
		uint64_t * cur   = start;
		
		while (start < end) {
			
			cnt = 0;
			cur = start;
			while ((cur < end) && is_TEXT_cstring(lf, *cur)) { cur++; cnt++; }
			if (cnt > 3) {
				cur = start;
				*profile_count = 0;
				while ((cur < end) && is_TEXT_cstring(lf, *cur)) { (*profile_count)++; cur++; } 
				return (uint8_t *)start;
			}
			
			start++;
		}
	} else {
		uint32_t * start = (uint32_t *) vmaddr_to_data(lf, lf->__DATA__const);
		uint32_t * end   = (uint32_t *) vmaddr_to_data(lf, lf->__DATA__const + lf->__DATA__constsize);
		uint32_t * cur   = start;
		
		while (start < end) {
			
			cnt = 0;
			cur = start;
			while ((cur < end) && is_TEXT_cstring(lf, *cur)) { cur++; cnt++; }
			if (cnt > 3) {
				cur = start;
				*profile_count = 0;
				while ((cur < end) && is_TEXT_cstring(lf, *cur)) { (*profile_count)++; cur++; } 
				return (uint8_t *)start;
			}
			
			start++;
		}
	}
	return NULL;
}

uint8_t * find_profile_table(struct loaded_macho * lf, int profile_count)
{
	/* we scan the __DATA::__const section for a 
	   list of pointers of length profile_count to __DATA::__data */
	int cnt = 0;
	
	if (lf->is64) {
		uint64_t * start = (uint64_t *) vmaddr_to_data(lf, lf->__DATA__const);
		uint64_t * end   = (uint64_t *) vmaddr_to_data(lf, lf->__DATA__const + lf->__DATA__constsize);
		uint64_t * cur   = start;
		
		while (start < end) {
			
			cnt = 0;
			cur = start;
			while ((cur < end) && is_DATA_data(lf, *cur)) { 
				/* validate the data */
				if (!is_valid_data(lf, *cur, 2*sizeof(uint64_t))) break;
				uint64_t * data = (uint64_t *) vmaddr_to_data(lf, *cur);
				if (!is_valid_data(lf, data[0], data[1])) break;
				cur++; cnt++; 
			}
			if (cnt == profile_count) {
				return (uint8_t *)start;
			}
			
			start++;
		}
	} else {
		uint32_t * start = (uint32_t *) vmaddr_to_data(lf, lf->__DATA__const);
		uint32_t * end   = (uint32_t *) vmaddr_to_data(lf, lf->__DATA__const + lf->__DATA__constsize);
		uint32_t * cur   = start;
		
		while (start < end) {
			
			cnt = 0;
			cur = start;
			while ((cur < end) && is_DATA_data(lf, *cur)) { 
				/* validate the data */
				if (!is_valid_data(lf, *cur, 2*sizeof(uint32_t))) break;
				uint32_t * data = (uint32_t *) vmaddr_to_data(lf, *cur);
				if (!is_valid_data(lf, data[0], data[1])) break;
				cur++; cnt++; 
			}
			if (cnt == profile_count) {
				return (uint8_t *)start;
			}
			
			start++;
		}
	}
	return NULL;
}

void dump_sandbox_profiles(struct loaded_macho *lf, uint8_t * profile_names, uint8_t * profile_table, char * name_prefix)
{
	char filename[1024];
	FILE *outf = NULL;
	
	if (lf->is64) {
		uint64_t * pn = (uint64_t *) profile_names;
		uint64_t * pt = (uint64_t *) profile_table;
		
		while (is_TEXT_cstring(lf, *pn)) {
			int r = snprintf((char *)&filename, sizeof(filename), "%s%s.bin", name_prefix, vmaddr_to_data(lf, *pn));
			if (r >= sizeof(filename)) {
				fprintf(stderr, "[-] cannot dump profile %s because filename would be too long %s.", vmaddr_to_data(lf, *pn), filename);
				pn++;
				continue;
			}
			outf = fopen(filename, "w+");
			if (!outf) {
				fprintf(stderr, "[-] cannot dump profile %s because cannot create output file %s.", vmaddr_to_data(lf, *pn), filename);
				pn++;
				continue;
			}
			
			if (!silent) {
				printf("[+] dumping built-in binary profile '%s' to file '%s'...\n", vmaddr_to_data(lf, *pn), filename);
			}
			uint64_t * data = (uint64_t *) vmaddr_to_data(lf, *pt);
			fwrite(vmaddr_to_data(lf, data[0]), 1, data[1], outf);
			
			fclose(outf);
			
			pn++;
			pt++;
		}	
	} else {
		uint32_t * pn = (uint32_t *) profile_names;
		uint32_t * pt = (uint32_t *) profile_table;
		
		while (is_TEXT_cstring(lf, *pn)) {
			int r = snprintf((char *)&filename, sizeof(filename), "%s%s.bin", name_prefix, vmaddr_to_data(lf, *pn));
			if (r >= sizeof(filename)) {
				fprintf(stderr, "[-] cannot dump profile %s because filename would be too long %s.", vmaddr_to_data(lf, *pn), filename);
				pn++;
				continue;
			}
			outf = fopen(filename, "w+");
			if (!outf) {
				fprintf(stderr, "[-] cannot dump profile %s because cannot create output file %s.", vmaddr_to_data(lf, *pn), filename);
				pn++;
				continue;
			}
			
			if (!silent) {
				printf("[+] dumping built-in binary profile '%s' to file '%s'...\n", vmaddr_to_data(lf, *pn), filename);
			}
			uint32_t * data = (uint32_t *) vmaddr_to_data(lf, *pt);
			fwrite(vmaddr_to_data(lf, data[0]), 1, data[1], outf);
			
			fclose(outf);
			
			pn++;
			pt++;
		}	
	}
	
	if (!silent) {
		printf("[+] done.\n");
	} 
}

int main(int argc, char **argv)
{
	struct loaded_macho lf;
	int error = 0;
	int profile_count = 0;
	uint8_t * profile_names;
	uint8_t * profile_table;
	char * pname = argv[0];
	char * outprefix = "./";
	int ch, help = 0;
	
	while ((ch = getopt(argc, argv, "o:sh")) != -1) {
		switch (ch) {
			case 's': silent = 1; break; 
			case 'o': outprefix = optarg; break; 
			case 'h': help = 1; break; 
		} 
	};

	argc -= optind;
	argv += optind;

	if ((argc != 1) || (help)) {
		fprintf(stderr, "extract_sbprofiles - a sandboxd built-in binary profiles extractor for iOS and OS X\n");
		fprintf(stderr, "Copyright (C) 2015 Stefan Esser / SektionEins GmbH <stefan@sektioneins.de>\n\n");
		fprintf(stderr, "Usage: %s [-s|-h] [-o outprefix] [sandboxd] \n\n", pname);
		fprintf(stderr, "   -s            silent mode - no output\n");
		fprintf(stderr, "   -h            show this help\n");
		fprintf(stderr, "   -o outprefix  prefix output filename with 'outprefix'\n");
		fprintf(stderr, "   sandboxd      file containing the iOS / OS X sandbox daemon usually /usr/libexec/sandboxd\n\n");
		_exit(0);
	}

	if (!silent) {
		printf("extract_sbprofiles - a sandbox binary profiles extractor for iOS and OS X\n");
		printf("Copyright (C) 2015 Stefan Esser / SektionEins GmbH <stefan@sektioneins.de>\n\n");
	}

	if (load_macho_into_memory(argv[0], &lf, &error) != LOAD_MACHO_SUCCESS) {
		fprintf(stderr, "[-] error: cannot load sandboxd into memory - error code %d\n", error);
		goto error;
	}
	
	profile_names = find_profile_nametable(&lf, &profile_count);
	
	if (!profile_names) {
		fprintf(stderr, "[-] error: cannot find built-in sandbox profile names.");
		goto error;
	}
	
	if (!silent) {
		printf("[+] Found %u built-in profiles.\n", profile_count);		
	}
	
	profile_table = find_profile_table(&lf, profile_count);
	
	if (!profile_table) {
		fprintf(stderr, "[-] error: cannot find built-in sandbox profile table.");
		goto error;
	}
	
	dump_sandbox_profiles(&lf, profile_names, profile_table, outprefix);

	destroy_loaded_file(&lf);
	return 0;
error:
	destroy_loaded_file(&lf);
	_exit(1);
}
/*
 * compile_sb - a sandbox script to binary compiler for iOS and OS X
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

struct sb_profile {
	unsigned int type;
	void * data;
	size_t data_len;
};

struct sb_profile * sandbox_compile_file(char *path, int n, char **error);
void sandbox_free_profile(struct sb_profile *profile); 

int main(int argc, char *argv[])
{
	int written;
	char *path = NULL, *outname = NULL;
	struct sb_profile * compiled_profile = NULL;
	FILE *outf = NULL;
	char *error = NULL;

	fprintf(stderr, "compile_sb - a sandbox script to binary compiler for iOS and OS X\n");
	fprintf(stderr, "Copyright (C) 2015 Stefan Esser / SektionEins GmbH <stefan@sektioneins.de>\n\n");
	if (argc != 3) {
		fprintf(stderr, "Usage: %s sandboxscript.sb output.bin\n\n", argv[0]);
		fprintf(stderr, "   sandboxscript.sb   file containing a scripted sandbox profile\n");
		fprintf(stderr, "   output.bin         file to write a compiled binary sandbox profile to\n\n");
		_exit(0);
	}

	path = realpath(argv[1], NULL); /* we need full path here */
	outname = argv[2];
	
	fprintf(stderr, "[+] compiling sandbox profile: %s\n", path);
	compiled_profile = sandbox_compile_file(path, 0, &error);
	if (compiled_profile == NULL) {
		fprintf(stderr, "[-] error compiling sandbox profile: %s\n", error);
		_exit(1);
	}

	outf = fopen(outname, "wb");
	if (outf == NULL) {
		sandbox_free_profile(compiled_profile);
		fprintf(stderr, "[-] error cannot open file for output: %s\n", outname);
		_exit(1);		
	}

	written = fwrite(compiled_profile->data, 1, compiled_profile->data_len, outf);
	if (written != compiled_profile->data_len) {
		fclose(outf);
		sandbox_free_profile(compiled_profile);
		fprintf(stderr, "[-] error unable to write to file: %s\n", outname);
		_exit(1);
	}
	
	fclose(outf);
	sandbox_free_profile(compiled_profile);

	printf("[+] compiled sandbox profile written to: %s\n", outname);

	return 0;
}

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2016 Maxime Chevallier
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.*/

/*  Read extended CSD registers from mmc device */

/* Useful to parse ext_csd file, located in debugfs */

#include<stdio.h>
#include<stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(int argc, char **argv){

	char *filename = NULL;
	char *content = NULL;
	uint offset = 0;
	uint nb_bytes = 0;
	int fd = 0;
	int i = 0;

	if(argc != 4){
		printf("Usage : read_ext_csd ext_csd_file offset nb_bytes\n");
		return 1;
	}

	filename = argv[1];
	sscanf(argv[2], "%u", &offset);
	sscanf(argv[3], "%u", &nb_bytes);

	fd = open(filename, O_RDONLY);

	if(!fd){
		printf("Cannot open %s\n", filename);
		return 2;
	}

	lseek(fd, 2 * offset, SEEK_SET);

	content = (char *)malloc( 2 *nb_bytes * sizeof(char) );
	read(fd, content, 2 * nb_bytes);
	close(fd);

	for(i = 0; i < nb_bytes; i++){
		printf("%c%c ", content[2*i], content[2*i+1]);
		if(!((i+1)%10))
			printf("\n");
	}
	printf("\n");
	
	free(content);

	return 0;
}

#include "packet.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

void usage() {
	printf("./log_reader log_file\n");
	exit(1);
}

int main( int argc, char **argv ) {

	if (argc != 2)
		usage();

	int fd = open(argv[1], O_RDONLY);

	if (!fd) {
		printf("Cannot open %s\n", argv[1]);
		return 1;
	}

	t_packet *p = read_next_packet(fd);
	while(p) {

		int i;
		for (i = 0; i < p->nb_info; i++) {
			char addr[18];
			ba2str(&p->infos[0]->bdaddr, addr);

			printf("%s\n", addr);
		}

		packet_free(p);

		p = read_next_packet(fd);
	} 

	close(fd);
	return 0;
}

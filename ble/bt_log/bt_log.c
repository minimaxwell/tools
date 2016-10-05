#include "monitor.h"
#include <stdio.h>
#include <stdlib.h>

void usage() {
	printf("./bt_log log_file\n");
	exit(1);
}

int main( int argc, char **argv ) {

	if (argc != 2)
		usage();

	start_scan(argv[1]);

	return 0;
}

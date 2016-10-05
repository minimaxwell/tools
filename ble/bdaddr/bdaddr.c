#include <hwdb.h>
#include <stdlib.h>
#include <stdio.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

int main( int argc, char **argv ) {
	bdaddr_t bdaddr;
	char *addr = NULL;
	char *company = NULL;

	if (argc != 2) {
		printf("./bdaddr address\n");
		return 1;
	}

	addr = argv[1];
	str2ba(addr, &bdaddr);

	printf("%02x %02x %02x %02x %02x %02x\n",
			bdaddr.b[0],
			bdaddr.b[1],
			bdaddr.b[2],
			bdaddr.b[3],
			bdaddr.b[4],
			bdaddr.b[5]);

	if (!hwdb_get_company(bdaddr.b, &company)) {
		printf("Cannot get company from address %s\n", addr);
		return 1;
	}

	if( company )
		printf("%s\n", company);

	free(company);

	return 0;
}

#include "report.h"
#include "report_reader.h"

#include <stdio.h>
#include <glib.h>

int main( int argc, char **argv ) {

	if(argc != 2) {
		printf("./report file\n");
		return 1;
	}

	GSList *ignore_list = NULL;
	ignore_list = g_slist_prepend( ignore_list, "Num reports" );
	ignore_list = g_slist_prepend( ignore_list, "RSSI" );
	ignore_list = g_slist_prepend( ignore_list, "Data length" );

	GSList *reports = read_reports(argv[1], ignore_list);
	GSList *elem = reports;

	while (elem) {
		print_report( (t_report *) elem->data);
		report_free( (t_report *) elem->data );
		elem = elem->next;
	}

	g_slist_free(reports);

	return 0;
}

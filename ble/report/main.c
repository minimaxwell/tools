#include "report.h"
#include "report_reader.h"

#include <stdio.h>
#include <glib.h>

int main( int argc, char **argv ) {

	GSList *elem = NULL;

	if(argc != 2) {
		printf("./report file\n");
		return 1;
	}

	GSList *ignore_list = NULL;
	ignore_list = g_slist_prepend( ignore_list, "Num reports" );
	ignore_list = g_slist_prepend( ignore_list, "RSSI" );
	ignore_list = g_slist_prepend( ignore_list, "Data length" );
	ignore_list = g_slist_prepend( ignore_list, "TX power" );

	GSList *reports = read_reports(argv[1], ignore_list);
/*	
	elem = reports;
	while (elem) {
		print_report( (t_report *) elem->data );
		elem = elem->next;
	}
*/
	GSList *merge_list = NULL;

	merge_list = g_slist_prepend( merge_list, "Flags");
	merge_list = g_slist_prepend( merge_list, "Event type");
	merge_list = g_slist_prepend( merge_list, "Address type");
	merge_list = g_slist_prepend( merge_list, "Service Data (UUID 0xfe9f)");
	merge_list = g_slist_prepend( merge_list, "16-bit Service UUIDs (complete)");
	merge_list = g_slist_prepend( merge_list, "128-bit Service UUIDs (partial)");
	merge_list = g_slist_prepend( merge_list, "Company");
	merge_list = g_slist_prepend( merge_list, "Name (complete)");
	merge_list = g_slist_prepend( merge_list, "Name (short)");

	GSList *devices = get_devices_by_field(reports, "Address", merge_list);

	elem = devices;
	while (elem) {
		print_device( (t_device *) elem->data);
		elem = elem->next;
	}

	return 0;
}

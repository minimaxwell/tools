#include "report.h"

#include <stdbool.h>
#include <glib.h>
#include <gio/gio.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

void field_free(t_field *field) {

	free(field->name);
	if(field->value)
		free(field->value);

	if(field->infos)
		g_slist_free_full(field->infos, free);

	free(field);
}

void report_free(t_report *report) {

	if (report->fields)
		g_slist_free_full(report->fields, (GDestroyNotify) field_free);

	free(report);
}

void device_free(t_device *device) {

	if (device->encounters)
		g_slist_free_full(device->encounters, (GDestroyNotify) free);
	if (device->fields)
		g_slist_free_full(device->fields, (GDestroyNotify) field_free);

	free(device);
}

t_field *field_create(char *name, char *value) {
	t_field *field = malloc(sizeof(t_field));
	field->name = name;
	field->value = value;
	field->infos = NULL;
	return field;
}

void field_add_info(t_field *field, char *info) {
	field->infos = g_slist_append( field->infos, info);
}

t_report *report_create(long long timestamp) {
	t_report *report = malloc(sizeof(t_report));

	report->timestamp = timestamp;

	report->fields = NULL;

	return report;
}

static gint fields_compare_by_name(gconstpointer f, gconstpointer f_n) {
	t_field *field = (t_field *) f;
	char *field_name = (char *) f_n;
	return g_strcmp0(field->name, field_name);
}

static t_field *list_get_field(GSList *list, char *name) {

	GSList *elem = g_slist_find_custom( list,
										name,
										(GCompareFunc) fields_compare_by_name); 

	if (elem) {
		return (t_field *) elem->data;
	} else {
		return NULL;
	}

}

static GSList *list_add_field(GSList *list, t_field *field, bool replace) {
	t_field *f;

	if (replace) {
		/* Search a field with the same name */
		f = list_get_field(list, field->name);
		
		if (f) {
			list = g_slist_remove(list, f);
			field_free(f);
		}

	}

	list = g_slist_append(list, field);

	return list;
}

/* The report takes ownership of the field */
void report_add_field(t_report *report, t_field *field, bool replace) {
	report->fields = list_add_field(report->fields, field, replace);
}

t_field *report_get_field(t_report *report, char *name) {
	return list_get_field(report->fields, name);
}

t_device *device_create() {
	t_device *device = malloc(sizeof(t_device));

	device->nb_adv = 0;
	device->encounters = NULL;
	device->fields = NULL;

	return device;
}

static bool ignore(GSList *ignore_list, char *field_name) {
	if (!ignore_list)
		return false;

	return ( g_slist_find_custom( ignore_list,
								  field_name,
								  fields_compare_by_name) != NULL);
}

static bool replace(GSList *replace_list, char *field_name) {
	if (!replace_list)
		return false;

	return ( g_slist_find_custom( replace_list,
								  field_name,
								  fields_compare_by_name) != NULL);

}

void device_set_field( t_device *device, t_field *field ) {
	device->fields = list_add_field(device->fields, field, false);
}

void device_add_report( t_device *device,
						const t_report *report,
						GSList *ignore_list, GSList *replace_list) {

	t_field *f;

	long long *ts = malloc(sizeof(long long));
	*ts = report->timestamp;

	device->nb_adv++;
	device->encounters = g_slist_prepend(device->encounters, ts);

	/* Merge fields according to ignore list */
	GSList *rep_elem = report->fields;
	
	while (rep_elem) {
		
		f = (t_field *) rep_elem->data;

		if (!ignore(ignore_list, f->name)) {
			device->fields = list_add_field( device->fields,
											 f, replace(replace_list, f->name));
		}

		rep_elem = rep_elem->next;
	}
}

void print_field(t_field *field) {
	printf("        %s: %s", field->name, field->value);

	if( field->infos ) {
		GSList *elem = field->infos;

		while (elem) {
			printf("\n          %s", (char *)elem->data);
			elem = elem->next;
		}
	}

	printf("\n");
}

void print_report(t_report *report) {
	printf("report %llu\n", report->timestamp);

	GSList *elem = report->fields;

	while (elem) {
		print_field( (t_field *) elem->data);
		elem = elem->next;
	}
}

void print_device(t_device *device) {
	GSList *elem = device->fields;

	printf("Nb Adv : %d\n", device->nb_adv);
	while (elem) {
		print_field( (t_field *) elem->data);
		elem = elem->next;
	}

}

static t_device *get_device_by_field_value( GSList *devices, char *name, char *value) {
	GSList *elem = devices;
	t_device *device;
	t_field *field;

	while (elem) {
		device = (t_device *) elem->data;
		field = list_get_field(device->fields, name);

		if (field) {
			if (!g_strcmp0(field->value, value))
				return device;
		}

		elem = elem->next;
	}

	return NULL;
}

GSList *get_devices_by_field(GSList *reports, char *name, GSList *merge_list) {
	GSList *elem;
	GSList *devices = NULL;
	GSList *replace_list = NULL;
	t_device *device;
	t_report *report;
	t_field *field;
	
	t_field *ign_field = field_create(name, NULL);
	replace_list = g_slist_prepend( replace_list, ign_field );

	for (elem = merge_list; elem; elem = elem->next) {
		ign_field = field_create( g_strdup((char *) elem->data), NULL);
		replace_list = g_slist_prepend( replace_list, ign_field);
	}

	for (elem = reports ;elem ; elem = elem->next) {
		report = (t_report *) elem->data;
		field = report_get_field(report, name);

		if (!field) {
			printf("Dropping report, no field %s\n", name);
			print_report(report);
			continue;
		}

		device = get_device_by_field_value( devices, name, field->value );
		
		if (!device) {
			printf("Creating device %s = %s\n", name, field->value);
			/* There aren't a device for this field */
			device = device_create();
			device_add_report( device, report, NULL, NULL);

			devices = g_slist_prepend( devices, device );
		} else {
			/* A device already exists */
			device_add_report( device, report, NULL, replace_list );
		}

	}

	return devices;
}

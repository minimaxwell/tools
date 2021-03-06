#ifndef __REPORT_H__
#define __REPORT_H__

#include <glib.h>
#include <gio/gio.h>
#include <stdbool.h>

typedef struct {
	char *name;
	char *value;
	GSList *infos;
} t_field;

typedef struct {
	long long timestamp;
	GSList *fields;
} t_report;

typedef struct {
	int nb_adv;
	GSList *encounters;
	GSList *fields;
} t_device;

void field_free(t_field *field);

void report_free(t_report *report);

void device_free(t_device *device);

t_field *field_create(char *name, char *value); 

void field_add_info(t_field *field, char *info);

t_report *report_create(long long timestamp);

void report_add_field(t_report *report, t_field *field, bool replace);

t_field *report_get_field(t_report *report, char *name);

t_device *device_create();

void device_add_report( t_device *device, const t_report *report,
						GSList *ignore_list, GSList *replace_list);

void print_field(t_field *field);
void print_report(t_report *report);
void print_device(t_device *device);

GSList *get_devices_by_field( GSList *reports, char *name, GSList *replace_list);
#endif

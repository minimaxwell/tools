#include "report_reader.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <glib.h>

static int consume_spaces(char **line) {
	int spaces = 0;

	while( **line && **line == ' ' ) {
		spaces++;
		*line = *line + 1;
	}

	return spaces;
}

static char *consume_field_value(char **line) {
	char buff[256];
	int i = 0;

	consume_spaces(line);

	while (**line && **line != '(') {
		buff[i++] = **line;
		*line = *line + 1;
	}

	buff[i] = '\0';
	if (buff[0])
		return g_strdup(buff);
	else
		return NULL;
}

/* Dangerous assumtion : we will encounter a ':' */
static char *consume_field_name(char **line) {
	char buff[256];
	int i = 0;

	while ( **line && **line != ':' ) {
		buff[i++] = **line;
		*line = *line + 1;
	}

	buff[i] = '\0';

	if (**line == ':')
		*line = *line + 1;

	if (buff[0])
		return g_strdup(buff);
	else
		return NULL;

}

/* Dangerous assumption here : 
 * we consider that all '(' will be matched
 * by a ')' on the same line */
static char *consume_info(char **line) {
	char buff[256];
	int i = 0;

	if (!**line)
		return NULL;

	if(**line != '(')
		return NULL;

	/* Skip '(' */
	*line = *line + 1;

	while (**line && **line != ')') {
		buff[i++] = **line;
		*line = *line + 1;
	}

	buff[i] = '\0';
	if (buff[0])
		return g_strdup(buff);
	else
		return NULL;
}

static char *get_full_info_line(char *line) {
	return g_strdup(line);
}

static unsigned long long get_timestamp(char **line) {
	char buff[256];
	int i = 0;

	while (**line && **line != ']')
		*line = *line + 1;

	/* skip '[' */
	*line = *line + 1;

	consume_spaces(line);

	while (**line && **line != '.') {
		buff[i++] = **line;
		*line = *line + 1;
	}

	buff[i] = '\0';

	/* Remove '.' */
	if (i)
		buff[i-1] = '\0';

	if (buff[0])
		return (unsigned long long) atoll(buff);
	else
		return 0;

}


static bool is_new_event_line(char *line) {
	if (line[0] == '>')
		return true;
	else
		return false;
}

static bool is_valid_line(char *line) {
	if (line[strlen(line) - 1] != '\n') {
		printf("invalid line %s", line);
		return false;
	}
	
	return true;
}

static bool ignore_field(GSList *ignore_list, char *field_name) {
	GSList *elem = ignore_list;

	while (elem) {
		if (!g_strcmp0( (char *)elem->data, field_name) ) {
			return true;
		}

		elem = elem->next;
	}

	return false;
}

GSList *read_reports(const char *file, GSList *ignore_list) {
    GSList *reports = NULL;
	char *buff = NULL;
	char *line = NULL;
	char *name, *value, *info;
	size_t len = 0;
	int nb_spaces;
	t_field *current_field = NULL;
	t_report *current_report = NULL;

	FILE *fp = fopen(file, "r");
	if (!fp) {
		printf("Cannot open %s\n", file);
		return NULL;
	}

	/* Get to start of first event */
	while ( getline(&buff, &len, fp) != -1 ) {
		if (!is_new_event_line(buff)) {
			break;
		}
	}

	do {
		line = buff;
		if (is_valid_line(line)) {
			/* remove trailing '\n' */
			line[ strlen(line) - 1] = '\0';
		}else{
			continue;
		}
		
		if (is_new_event_line(line)) {
			if( current_report )
				reports = g_slist_append(reports, current_report);

			unsigned long long timestamp = get_timestamp(&line);
			current_report = report_create(timestamp);
			continue;
		}
		
		nb_spaces = consume_spaces(&line);

		if (nb_spaces == 8) {
			name = consume_field_name( &line );
			
			if(ignore_field(ignore_list, name))
				continue;

			value = consume_field_value( &line );
			info = consume_info( &line );

			if (name && value) {
				if (current_field && current_report) {
					report_add_field( current_report, current_field, false);
				}
				
				current_field = field_create(name, value);

				if (info)
					field_add_info(current_field, info);
			}

			continue;
		}

		if (nb_spaces == 10) {
			if( current_field )
				field_add_info( current_field, get_full_info_line(line)); 
			continue;
		}

	} while ( getline(&buff, &len, fp) != -1);

	if ( current_field && current_report )
		report_add_field( current_report, current_field, false );

	if ( current_report )
		reports = g_slist_append( reports, current_report );

	fclose(fp);

	if(buff)
		free(buff);

    return reports;
}

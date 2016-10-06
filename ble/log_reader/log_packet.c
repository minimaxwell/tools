#include "log_packet.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>


t_packet *read_next_packet(int fd) {
	t_packet *packet;

	uint64_t timestamp;
	uint16_t len;
	uint8_t type;
	uint8_t *data;

	le_advertising_info **infos;
	uint8_t nb_info;

	if (read(fd, &timestamp, 8) != 8) {
		printf("Cannot read timestamp\n");
		return NULL;
	}

	if (read(fd, &len, 2) != 2) {
		printf("Cannot read length\n");
		return NULL;
	}
	
	if (read(fd, &type, 1) != 1) {
		printf("Cannot read type\n");
		return NULL;
	}
	len--;

	if (read(fd, &nb_info, 1) != 1) {
		printf("Cannot read nb adv info\n");
		len--;
	}

	data = malloc(len);
	if (read(fd, data, len) != len) {
		printf("Cannot read data\n");
		return NULL;
	}

	infos = malloc(nb_info * sizeof(le_advertising_info *));

	int i = 0;
	while (i < nb_info) {
		infos[i] = (le_advertising_info *) data;
		data += sizeof(le_advertising_info) + infos[i]->length;
		len -= sizeof(le_advertising_info) + infos[i]->length;
		i++;
	}

	packet = malloc(sizeof(t_packet));

	packet->timestamp = timestamp;
	packet->nb_info = nb_info;
	packet->infos = infos;
	return packet;
}

void packet_free(t_packet *p) {

	free(p->infos[0]);

	free(p->infos);
	free(p);
}

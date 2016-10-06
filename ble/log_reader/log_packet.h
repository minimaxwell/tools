#ifndef __LOG_PACKET_H__
#define __LOG_PACKET_H__

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

typedef struct {
	uint64_t timestamp;
	uint8_t nb_info;
	le_advertising_info **infos;
} t_packet;

t_packet *read_next_packet(int fd);

void packet_free(t_packet *p);

#endif

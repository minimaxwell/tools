#include "monitor.h"
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <signal.h>
#include <stdint.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#define EIR_FLAGS                   0x01  /* flags */
#define EIR_UUID16_SOME             0x02  /* 16-bit UUID, more available */
#define EIR_UUID16_ALL              0x03  /* 16-bit UUID, all listed */
#define EIR_UUID32_SOME             0x04  /* 32-bit UUID, more available */
#define EIR_UUID32_ALL              0x05  /* 32-bit UUID, all listed */
#define EIR_UUID128_SOME            0x06  /* 128-bit UUID, more available */
#define EIR_UUID128_ALL             0x07  /* 128-bit UUID, all listed */
#define EIR_NAME_SHORT              0x08  /* shortened local name */
#define EIR_NAME_COMPLETE           0x09  /* complete local name */
#define EIR_TX_POWER                0x0A  /* transmit power level */
#define EIR_DEVICE_ID               0x10  /* device ID */
static int signal_received = 0;

static time_t base_time;

static time_t get_timestamp() {
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return ts.tv_sec - base_time;
}

static void sigint_handler(int sig){
	signal_received = sig;
}

static int log_advertisements(int dd, int log_fd) {

	unsigned char buf[HCI_MAX_EVENT_SIZE], *ptr;
	struct hci_filter nf, of;
	struct sigaction sa;
	socklen_t olen;
	int len;
	uint16_t len_wr;
	unsigned long nb_adv = 0;
	uint64_t timestamp;

	olen = sizeof(of);
	if (getsockopt(dd, SOL_HCI, HCI_FILTER, &of, &olen) < 0) {
		printf("Could not get socket options\n");
		return -1;
	}

	hci_filter_clear(&nf);
	hci_filter_set_ptype(HCI_EVENT_PKT, &nf);
	hci_filter_set_event(EVT_LE_META_EVENT, &nf);

	if (setsockopt(dd, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0) {
		printf("Could not set socket options\n");
		return -1;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_NOCLDSTOP;
	sa.sa_handler = sigint_handler;
	sigaction(SIGINT, &sa, NULL);

	while (1) {

		while ((len = read(dd, buf, sizeof(buf))) < 0) {
			if (errno == EINTR && signal_received == SIGINT) {
				len = 0;
				goto done;
			}

			if (errno == EAGAIN || errno == EINTR)
				continue;
			goto done;
		}

		timestamp = (uint64_t) get_timestamp();

		nb_adv++;

		ptr = buf + (1 + HCI_EVENT_HDR_SIZE);
		len -= (1 + HCI_EVENT_HDR_SIZE);

		len_wr = (uint16_t) len;

		/* Packets : 
		 * bytes [0..7] : timestamp in seconds( 0 is start of acquisition )
		 * bytes [8..9] : length of adv data
		 * bytes [10..10+len] : adv data
		 * */

		/* Use fixed-size types */
		write(log_fd, &timestamp, sizeof(uint64_t));
		write(log_fd, &len_wr, sizeof(uint16_t));

		if (write( log_fd, ptr, len) != len) {
			printf("Error writing to log file\n");
			goto done;
		}

	}

done:
	setsockopt(dd, SOL_HCI, HCI_FILTER, &of, sizeof(of));
	
	printf("Captured %llu advertisements\n", nb_adv);

	if (len < 0)
		return -1;

	return 0;
}

static void cmd_lescan(int dev_id, int log_fd) {
	int err, dd;
	uint8_t own_type = LE_RANDOM_ADDRESS;
	uint8_t scan_type = 0x01;
	uint8_t filter_policy = 0x00;
	uint16_t interval = htobs(0x0010);
	uint16_t window = htobs(0x0010);
	uint8_t filter_dup = 0x00;


	if (dev_id < 0)
		dev_id = hci_get_route(NULL);

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		perror("Could not open device");
		exit(1);
	}

	err = hci_le_set_scan_parameters(dd, scan_type, interval, window,
						own_type, filter_policy, 10000);
	if (err < 0) {
		perror("Set scan parameters failed");
		exit(1);
	}

	err = hci_le_set_scan_enable(dd, 0x01, filter_dup, 10000);
	if (err < 0) {
		perror("Enable scan failed");
		exit(1);
	}

	err = log_advertisements(dd, log_fd);
	if (err < 0) {
		perror("Could not receive advertising events");
		exit(1);
	}

	err = hci_le_set_scan_enable(dd, 0x00, filter_dup, 10000);
	if (err < 0) {
		perror("Disable scan failed");
		exit(1);
	}

	hci_close_dev(dd);
}

void start_scan(const char *filename) {

	struct timespec ts;
	int dev_id, log_fd;

	/* hci fd */
	dev_id = hci_devid("hci0");
	
	/* open log file ( binary ) */
	log_fd = open(filename, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);

	if (!log_fd) {
		printf("cannot open %s\n", filename);
		goto fail_log;
	}

	/* init base time */
	clock_gettime(CLOCK_MONOTONIC, &ts);
	base_time = ts.tv_sec;

	cmd_lescan(dev_id, log_fd);

fail_log:
	close(log_fd);

	hci_close_dev(dev_id);
}

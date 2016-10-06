/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2014  Intel Corporation
 *  Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include "bt.h"
#include "ll.h"
#include "hwdb.h"
#include "keys.h"
#include "uuid.h"
#include "control.h"
#include "vendor.h"
#include "intel.h"
#include "broadcom.h"
#include "packet.h"

#define COLOR_INDEX_LABEL		COLOR_WHITE
#define COLOR_TIMESTAMP			COLOR_YELLOW

#define COLOR_NEW_INDEX			COLOR_GREEN
#define COLOR_DEL_INDEX			COLOR_RED
#define COLOR_OPEN_INDEX		COLOR_GREEN
#define COLOR_CLOSE_INDEX		COLOR_RED
#define COLOR_INDEX_INFO		COLOR_GREEN
#define COLOR_VENDOR_DIAG		COLOR_YELLOW

#define COLOR_HCI_COMMAND		COLOR_BLUE
#define COLOR_HCI_COMMAND_UNKNOWN	COLOR_WHITE_BG

#define COLOR_HCI_EVENT			COLOR_MAGENTA
#define COLOR_HCI_EVENT_UNKNOWN		COLOR_WHITE_BG

#define COLOR_HCI_ACLDATA		COLOR_CYAN
#define COLOR_HCI_SCODATA		COLOR_YELLOW

#define COLOR_UNKNOWN_ERROR		COLOR_WHITE_BG
#define COLOR_UNKNOWN_FEATURE_BIT	COLOR_WHITE_BG
#define COLOR_UNKNOWN_COMMAND_BIT	COLOR_WHITE_BG
#define COLOR_UNKNOWN_EVENT_MASK	COLOR_WHITE_BG
#define COLOR_UNKNOWN_LE_STATES		COLOR_WHITE_BG
#define COLOR_UNKNOWN_SERVICE_CLASS	COLOR_WHITE_BG
#define COLOR_UNKNOWN_PKT_TYPE_BIT	COLOR_WHITE_BG

#define COLOR_PHY_PACKET		COLOR_BLUE

static time_t time_offset = ((time_t) -1);
static int priority_level = BTSNOOP_PRIORITY_INFO;
static unsigned long filter_mask = 0;
static bool index_filter = false;
static uint16_t index_number = 0;
static uint16_t index_current = 0;

#define UNKNOWN_MANUFACTURER 0xffff

#define MAX_CONN 16

struct conn_data {
	uint16_t handle;
	uint8_t  type;
};

static struct conn_data conn_list[MAX_CONN];

static void assign_handle(uint16_t handle, uint8_t type)
{
	int i;

	for (i = 0; i < MAX_CONN; i++) {
		if (conn_list[i].handle == 0x0000) {
			conn_list[i].handle = handle;
			conn_list[i].type = type;
			break;
		}
	}
}

static void release_handle(uint16_t handle)
{
	int i;

	for (i = 0; i < MAX_CONN; i++) {
		if (conn_list[i].handle == handle) {
			conn_list[i].handle = 0x0000;
			conn_list[i].type = 0x00;
			break;
		}
	}
}

static uint8_t get_type(uint16_t handle)
{
	int i;

	for (i = 0; i < MAX_CONN; i++) {
		if (conn_list[i].handle == handle)
			return conn_list[i].type;
	}

	return 0xff;
}


static const struct {
	uint8_t error;
	const char *str;
} error2str_table[] = {
	{ 0x00, "Success"						},
	{ 0x01, "Unknown HCI Command"					},
	{ 0x02, "Unknown Connection Identifier"				},
	{ 0x03, "Hardware Failure"					},
	{ 0x04, "Page Timeout"						},
	{ 0x05, "Authentication Failure"				},
	{ 0x06, "PIN or Key Missing"					},
	{ 0x07, "Memory Capacity Exceeded"				},
	{ 0x08, "Connection Timeout"					},
	{ 0x09, "Connection Limit Exceeded"				},
	{ 0x0a, "Synchronous Connection Limit to a Device Exceeded"	},
	{ 0x0b, "ACL Connection Already Exists"				},
	{ 0x0c, "Command Disallowed"					},
	{ 0x0d, "Connection Rejected due to Limited Resources"		},
	{ 0x0e, "Connection Rejected due to Security Reasons"		},
	{ 0x0f, "Connection Rejected due to Unacceptable BD_ADDR"	},
	{ 0x10, "Connection Accept Timeout Exceeded"			},
	{ 0x11, "Unsupported Feature or Parameter Value"		},
	{ 0x12, "Invalid HCI Command Parameters"			},
	{ 0x13, "Remote User Terminated Connection"			},
	{ 0x14, "Remote Device Terminated due to Low Resources"		},
	{ 0x15, "Remote Device Terminated due to Power Off"		},
	{ 0x16, "Connection Terminated By Local Host"			},
	{ 0x17, "Repeated Attempts"					},
	{ 0x18, "Pairing Not Allowed"					},
	{ 0x19, "Unknown LMP PDU"					},
	{ 0x1a, "Unsupported Remote Feature / Unsupported LMP Feature"	},
	{ 0x1b, "SCO Offset Rejected"					},
	{ 0x1c, "SCO Interval Rejected"					},
	{ 0x1d, "SCO Air Mode Rejected"					},
	{ 0x1e, "Invalid LMP Parameters / Invalid LL Parameters"	},
	{ 0x1f, "Unspecified Error"					},
	{ 0x20, "Unsupported LMP Parameter Value / "
		"Unsupported LL Parameter Value"			},
	{ 0x21, "Role Change Not Allowed"				},
	{ 0x22, "LMP Response Timeout / LL Response Timeout"		},
	{ 0x23, "LMP Error Transaction Collision"			},
	{ 0x24, "LMP PDU Not Allowed"					},
	{ 0x25, "Encryption Mode Not Acceptable"			},
	{ 0x26, "Link Key cannot be Changed"				},
	{ 0x27, "Requested QoS Not Supported"				},
	{ 0x28, "Instant Passed"					},
	{ 0x29, "Pairing With Unit Key Not Supported"			},
	{ 0x2a, "Different Transaction Collision"			},
	{ 0x2b, "Reserved"						},
	{ 0x2c, "QoS Unacceptable Parameter"				},
	{ 0x2d, "QoS Rejected"						},
	{ 0x2e, "Channel Classification Not Supported"			},
	{ 0x2f, "Insufficient Security"					},
	{ 0x30, "Parameter Out Of Manadatory Range"			},
	{ 0x31, "Reserved"						},
	{ 0x32, "Role Switch Pending"					},
	{ 0x33, "Reserved"						},
	{ 0x34, "Reserved Slot Violation"				},
	{ 0x35, "Role Switch Failed"					},
	{ 0x36, "Extended Inquiry Response Too Large"			},
	{ 0x37, "Secure Simple Pairing Not Supported By Host"		},
	{ 0x38, "Host Busy - Pairing"					},
	{ 0x39, "Connection Rejected due to No Suitable Channel Found"	},
	{ 0x3a, "Controller Busy"					},
	{ 0x3b, "Unacceptable Connection Parameters"			},
	{ 0x3c, "Directed Advertising Timeout"				},
	{ 0x3d, "Connection Terminated due to MIC Failure"		},
	{ 0x3e, "Connection Failed to be Established"			},
	{ 0x3f, "MAC Connection Failed"					},
	{ 0x40, "Coarse Clock Adjustment Rejected "
		"but Will Try to Adjust Using Clock Dragging"		},
	{ }
};

static void print_error(const char *label, uint8_t error)
{
	const char *str = "Unknown";
	const char *color_on, *color_off;
	bool unknown = true;
	int i;

	for (i = 0; error2str_table[i].str; i++) {
		if (error2str_table[i].error == error) {
			str = error2str_table[i].str;
			unknown = false;
			break;
		}
	}

	if (use_color()) {
		if (error) {
			if (unknown)
				color_on = COLOR_UNKNOWN_ERROR;
			else
				color_on = COLOR_RED;
		} else
			color_on = COLOR_GREEN;
		color_off = COLOR_OFF;
	} else {
		color_on = "";
		color_off = "";
	}

	print_field("%s: %s%s%s (0x%2.2x)", label,
				color_on, str, color_off, error);
}

static void print_status(uint8_t status)
{
	print_error("Status", status);
}

static void print_reason(uint8_t reason)
{
	print_error("Reason", reason);
}

static void print_addr_type(const char *label, uint8_t addr_type)
{
	const char *str;

	switch (addr_type) {
	case 0x00:
		str = "Public";
		break;
	case 0x01:
		str = "Random";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("%s: %s (0x%2.2x)", label, str, addr_type);
}

static void print_own_addr_type(uint8_t addr_type)
{
	const char *str;

	switch (addr_type) {
	case 0x00:
	case 0x02:
		str = "Public";
		break;
	case 0x01:
	case 0x03:
		str = "Random";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Own address type: %s (0x%2.2x)", str, addr_type);
}

static void print_peer_addr_type(const char *label, uint8_t addr_type)
{
	const char *str;

	switch (addr_type) {
	case 0x00:
		str = "Public";
		break;
	case 0x01:
		str = "Random";
		break;
	case 0x02:
		str = "Resolved Public";
		break;
	case 0x03:
		str = "Resolved Random";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("%s: %s (0x%2.2x)", label, str, addr_type);
}

static void print_addr_resolve(const char *label, const uint8_t *addr,
					uint8_t addr_type, bool resolve)
{
	const char *str;
	char *company;

	switch (addr_type) {
	case 0x00:
	case 0x02:
		if (!hwdb_get_company(addr, &company))
			company = NULL;

		if (company) {
			print_field("%s: %2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X"
					" (%s)", label, addr[5], addr[4],
							addr[3], addr[2],
							addr[1], addr[0],
							company);
			free(company);
		} else {
			print_field("%s: %2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X"
					" (OUI %2.2X-%2.2X-%2.2X)", label,
						addr[5], addr[4], addr[3],
						addr[2], addr[1], addr[0],
						addr[5], addr[4], addr[3]);
		}
		break;
	case 0x01:
	case 0x03:
		switch ((addr[5] & 0xc0) >> 6) {
		case 0x00:
			str = "Non-Resolvable";
			break;
		case 0x01:
			str = "Resolvable";
			break;
		case 0x03:
			str = "Static";
			break;
		default:
			str = "Reserved";
			break;
		}

		print_field("%s: %2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X (%s)",
					label, addr[5], addr[4], addr[3],
					addr[2], addr[1], addr[0], str);

		if (resolve && (addr[5] & 0xc0) == 0x40) {
			uint8_t ident[6], ident_type;

			if (keys_resolve_identity(addr, ident, &ident_type)) {
				print_addr_type("  Identity type", ident_type);
				print_addr_resolve("  Identity", ident,
							ident_type, false);
			}
		}
		break;
	default:
		print_field("%s: %2.2X-%2.2X-%2.2X-%2.2X-%2.2X-%2.2X",
					label, addr[5], addr[4], addr[3],
					addr[2], addr[1], addr[0]);
		break;
	}
}

static void print_addr(const char *label, const uint8_t *addr,
						uint8_t addr_type)
{
	print_addr_resolve(label, addr, addr_type, true);
}

static void print_bdaddr(const uint8_t *bdaddr)
{
	print_addr("Address", bdaddr, 0x00);
}

static void print_lt_addr(uint8_t lt_addr)
{
	print_field("LT address: %d", lt_addr);
}

static void print_handle(uint16_t handle)
{
	print_field("Handle: %d", le16_to_cpu(handle));
}

static void print_phy_handle(uint8_t phy_handle)
{
	print_field("Physical handle: %d", phy_handle);
}

static const struct {
	uint8_t bit;
	const char *str;
} pkt_type_table[] = {
	{  1, "2-DH1 may not be used"	},
	{  2, "3-DH1 may not be used"	},
	{  3, "DM1 may be used"		},
	{  4, "DH1 may be used"		},
	{  8, "2-DH3 may not be used"	},
	{  9, "3-DH3 may not be used"	},
	{ 10, "DM3 may be used"		},
	{ 11, "DH3 may be used"		},
	{ 12, "3-DH5 may not be used"	},
	{ 13, "3-DH5 may not be used"	},
	{ 14, "DM5 may be used"		},
	{ 15, "DH5 may be used"		},
	{ }
};

static void print_pkt_type(uint16_t pkt_type)
{
	uint16_t mask;
	int i;

	print_field("Packet type: 0x%4.4x", le16_to_cpu(pkt_type));

	mask = le16_to_cpu(pkt_type);

	for (i = 0; pkt_type_table[i].str; i++) {
		if (le16_to_cpu(pkt_type) & (1 << pkt_type_table[i].bit)) {
			print_field("  %s", pkt_type_table[i].str);
			mask &= ~(1 << pkt_type_table[i].bit);
		}
	}

	if (mask)
		print_text(COLOR_UNKNOWN_PKT_TYPE_BIT,
				"  Unknown packet types (0x%4.4x)", mask);
}

static const struct {
	uint8_t bit;
	const char *str;
} pkt_type_sco_table[] = {
	{  0, "HV1 may be used"		},
	{  1, "HV2 may be used"		},
	{  2, "HV3 may be used"		},
	{  3, "EV3 may be used"		},
	{  4, "EV4 may be used"		},
	{  5, "EV5 may be used"		},
	{  6, "2-EV3 may not be used"	},
	{  7, "3-EV3 may not be used"	},
	{  8, "2-EV5 may not be used"	},
	{  9, "3-EV5 may not be used"	},
	{ }
};

static void print_pkt_type_sco(uint16_t pkt_type)
{
	uint16_t mask;
	int i;

	print_field("Packet type: 0x%4.4x", le16_to_cpu(pkt_type));

	mask = le16_to_cpu(pkt_type);

	for (i = 0; pkt_type_sco_table[i].str; i++) {
		if (le16_to_cpu(pkt_type) & (1 << pkt_type_sco_table[i].bit)) {
			print_field("  %s", pkt_type_sco_table[i].str);
			mask &= ~(1 << pkt_type_sco_table[i].bit);
		}
	}

	if (mask)
		print_text(COLOR_UNKNOWN_PKT_TYPE_BIT,
				"  Unknown packet types (0x%4.4x)", mask);
}

static void print_iac(const uint8_t *lap)
{
	const char *str = "";

	if (lap[2] == 0x9e && lap[1] == 0x8b) {
		switch (lap[0]) {
		case 0x33:
			str = " (General Inquiry)";
			break;
		case 0x00:
			str = " (Limited Inquiry)";
			break;
		}
	}

	print_field("Access code: 0x%2.2x%2.2x%2.2x%s",
						lap[2], lap[1], lap[0], str);
}

static void print_auth_enable(uint8_t enable)
{
	const char *str;

	switch (enable) {
	case 0x00:
		str = "Authentication not required";
		break;
	case 0x01:
		str = "Authentication required for all connections";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Enable: %s (0x%2.2x)", str, enable);
}

static void print_encrypt_mode(uint8_t mode)
{
	const char *str;

	switch (mode) {
	case 0x00:
		str = "Encryption not required";
		break;
	case 0x01:
		str = "Encryption required for all connections";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Mode: %s (0x%2.2x)", str, mode);
}

static const struct {
	uint8_t bit;
	const char *str;
} svc_class_table[] = {
	{ 0, "Positioning (Location identification)"		},
	{ 1, "Networking (LAN, Ad hoc)"				},
	{ 2, "Rendering (Printing, Speaker)"			},
	{ 3, "Capturing (Scanner, Microphone)"			},
	{ 4, "Object Transfer (v-Inbox, v-Folder)"		},
	{ 5, "Audio (Speaker, Microphone, Headset)"		},
	{ 6, "Telephony (Cordless telephony, Modem, Headset)"	},
	{ 7, "Information (WEB-server, WAP-server)"		},
	{ }
};

static const struct {
	uint8_t val;
	const char *str;
} major_class_computer_table[] = {
	{ 0x00, "Uncategorized, code for device not assigned"	},
	{ 0x01, "Desktop workstation"				},
	{ 0x02, "Server-class computer"				},
	{ 0x03, "Laptop"					},
	{ 0x04, "Handheld PC/PDA (clam shell)"			},
	{ 0x05, "Palm sized PC/PDA"				},
	{ 0x06, "Wearable computer (Watch sized)"		},
	{ 0x07, "Tablet"					},
	{ }
};

static const char *major_class_computer(uint8_t minor)
{
	int i;

	for (i = 0; major_class_computer_table[i].str; i++) {
		if (major_class_computer_table[i].val == minor)
			return major_class_computer_table[i].str;
	}

	return NULL;
}

static const struct {
	uint8_t val;
	const char *str;
} major_class_phone_table[] = {
	{ 0x00, "Uncategorized, code for device not assigned"	},
	{ 0x01, "Cellular"					},
	{ 0x02, "Cordless"					},
	{ 0x03, "Smart phone"					},
	{ 0x04, "Wired modem or voice gateway"			},
	{ 0x05, "Common ISDN Access"				},
	{ }
};

static const char *major_class_phone(uint8_t minor)
{
	int i;

	for (i = 0; major_class_phone_table[i].str; i++) {
		if (major_class_phone_table[i].val == minor)
			return major_class_phone_table[i].str;
	}

	return NULL;
}

static const struct {
	uint8_t val;
	const char *str;
} major_class_av_table[] = {
	{ 0x00, "Uncategorized, code for device not assigned"	},
	{ 0x01, "Wearable Headset Device"			},
	{ 0x02, "Hands-free Device"				},
	{ 0x04, "Microphone"					},
	{ 0x05, "Loudspeaker"					},
	{ 0x06, "Headphones"					},
	{ 0x07, "Portable Audio"				},
	{ 0x08, "Car audio"					},
	{ 0x09, "Set-top box"					},
	{ 0x0a, "HiFi Audio Device"				},
	{ 0x0b, "VCR"						},
	{ 0x0c, "Video Camera"					},
	{ 0x0d, "Camcorder"					},
	{ 0x0e, "Video Monitor"					},
	{ 0x0f, "Video Display and Loudspeaker"			},
	{ 0x10, "Video Conferencing"				},
	{ 0x12, "Gaming/Toy"					},
	{ }
};

static const char *major_class_av(uint8_t minor)
{
	int i;

	for (i = 0; major_class_av_table[i].str; i++) {
		if (major_class_av_table[i].val == minor)
			return major_class_av_table[i].str;
	}

	return NULL;
}

static const struct {
	uint8_t val;
	const char *str;
} major_class_wearable_table[] = {
	{ 0x01, "Wrist Watch"	},
	{ 0x02, "Pager"		},
	{ 0x03, "Jacket"	},
	{ 0x04, "Helmet"	},
	{ 0x05, "Glasses"	},
	{ }
};

static const char *major_class_wearable(uint8_t minor)
{
	int i;

	for (i = 0; major_class_wearable_table[i].str; i++) {
		if (major_class_wearable_table[i].val == minor)
			return major_class_wearable_table[i].str;
	}

	return NULL;
}

static const struct {
	uint8_t val;
	const char *str;
	const char *(*func)(uint8_t minor);
} major_class_table[] = {
	{ 0x00, "Miscellaneous"						},
	{ 0x01, "Computer (desktop, notebook, PDA, organizers)",
						major_class_computer	},
	{ 0x02, "Phone (cellular, cordless, payphone, modem)",
						major_class_phone	},
	{ 0x03, "LAN /Network Access point"				},
	{ 0x04, "Audio/Video (headset, speaker, stereo, video, vcr)",
						major_class_av		},
	{ 0x05, "Peripheral (mouse, joystick, keyboards)"		},
	{ 0x06, "Imaging (printing, scanner, camera, display)"		},
	{ 0x07, "Wearable",			major_class_wearable	},
	{ 0x08, "Toy"							},
	{ 0x09, "Health"						},
	{ 0x1f, "Uncategorized, specific device code not specified"	},
	{ }
};

static void print_dev_class(const uint8_t *dev_class)
{
	uint8_t mask, major_cls, minor_cls;
	const char *major_str = NULL;
	const char *minor_str = NULL;
	int i;

	print_field("Class: 0x%2.2x%2.2x%2.2x",
			dev_class[2], dev_class[1], dev_class[0]);

	if ((dev_class[0] & 0x03) != 0x00) {
		print_field("  Format type: 0x%2.2x", dev_class[0] & 0x03);
		print_text(COLOR_ERROR, "  invalid format type");
		return;
	}

	major_cls = dev_class[1] & 0x1f;
	minor_cls = (dev_class[0] & 0xfc) >> 2;

	for (i = 0; major_class_table[i].str; i++) {
		if (major_class_table[i].val == major_cls) {
			major_str = major_class_table[i].str;

			if (!major_class_table[i].func)
				break;

			minor_str = major_class_table[i].func(minor_cls);
			break;
		}
	}

	if (major_str) {
		print_field("  Major class: %s", major_str);
		if (minor_str)
			print_field("  Minor class: %s", minor_str);
		else
			print_field("  Minor class: 0x%2.2x", minor_cls);
	} else {
		print_field("  Major class: 0x%2.2x", major_cls);
		print_field("  Minor class: 0x%2.2x", minor_cls);
	}

	if (dev_class[1] & 0x20)
		print_field("  Limited Discoverable Mode");

	if ((dev_class[1] & 0xc0) != 0x00) {
		print_text(COLOR_ERROR, "  invalid service class");
		return;
	}

	mask = dev_class[2];

	for (i = 0; svc_class_table[i].str; i++) {
		if (dev_class[2] & (1 << svc_class_table[i].bit)) {
			print_field("  %s", svc_class_table[i].str);
			mask &= ~(1 << svc_class_table[i].bit);
		}
	}

	if (mask)
		print_text(COLOR_UNKNOWN_SERVICE_CLASS,
				"  Unknown service class (0x%2.2x)", mask);
}

static const struct {
	uint16_t val;
	bool generic;
	const char *str;
} appearance_table[] = {
	{    0, true,  "Unknown"		},
	{   64, true,  "Phone"			},
	{  128, true,  "Computer"		},
	{  192, true,  "Watch"			},
	{  193, false, "Sports Watch"		},
	{  256, true,  "Clock"			},
	{  320, true,  "Display"		},
	{  384, true,  "Remote Control"		},
	{  448, true,  "Eye-glasses"		},
	{  512, true,  "Tag"			},
	{  576, true,  "Keyring"		},
	{  640, true,  "Media Player"		},
	{  704, true,  "Barcode Scanner"	},
	{  768, true,  "Thermometer"		},
	{  769, false, "Thermometer: Ear"	},
	{  832, true,  "Heart Rate Sensor"	},
	{  833, false, "Heart Rate Belt"	},
	{  896, true,  "Blood Pressure"		},
	{  897, false, "Blood Pressure: Arm"	},
	{  898, false, "Blood Pressure: Wrist"	},
	{  960, true,  "Human Interface Device"	},
	{  961, false, "Keyboard"		},
	{  962, false, "Mouse"			},
	{  963, false, "Joystick"		},
	{  964, false, "Gamepad"		},
	{  965, false, "Digitizer Tablet"	},
	{  966, false, "Card Reader"		},
	{  967, false, "Digital Pen"		},
	{  968, false, "Barcode Scanner"	},
	{ 1024, true,  "Glucose Meter"		},
	{ 1088, true,  "Running Walking Sensor"			},
	{ 1089, false, "Running Walking Sensor: In-Shoe"	},
	{ 1090, false, "Running Walking Sensor: On-Shoe"	},
	{ 1091, false, "Running Walking Sensor: On-Hip"		},
	{ 1152, true,  "Cycling"				},
	{ 1153, false, "Cycling: Cycling Computer"		},
	{ 1154, false, "Cycling: Speed Sensor"			},
	{ 1155, false, "Cycling: Cadence Sensor"		},
	{ 1156, false, "Cycling: Power Sensor"			},
	{ 1157, false, "Cycling: Speed and Cadence Sensor"	},
	{ 1216, true,  "Undefined"				},

	{ 3136, true,  "Pulse Oximeter"				},
	{ 3137, false, "Pulse Oximeter: Fingertip"		},
	{ 3138, false, "Pulse Oximeter: Wrist Worn"		},
	{ 3200, true,  "Weight Scale"				},
	{ 3264, true,  "Undefined"				},

	{ 5184, true,  "Outdoor Sports Activity"		},
	{ 5185, false, "Location Display Device"		},
	{ 5186, false, "Location and Navigation Display Device"	},
	{ 5187, false, "Location Pod"				},
	{ 5188, false, "Location and Navigation Pod"		},
	{ 5248, true,  "Undefined"				},
	{ }
};

static void print_appearance(uint16_t appearance)
{
	const char *str = NULL;
	int i, type = 0;

	for (i = 0; appearance_table[i].str; i++) {
		if (appearance_table[i].generic) {
			if (appearance < appearance_table[i].val)
				break;
			type = i;
		}

		if (appearance_table[i].val == appearance) {
			str = appearance_table[i].str;
			break;
		}
	}

	if (!str)
		str = appearance_table[type].str;

	print_field("Appearance: %s (0x%4.4x)", str, appearance);
}

static void print_num_broadcast_retrans(uint8_t num_retrans)
{
	print_field("Number of broadcast retransmissions: %u", num_retrans);
}

static void print_hold_mode_activity(uint8_t activity)
{
	print_field("Activity: 0x%2.2x", activity);

	if (activity == 0x00) {
		print_field("  Maintain current Power State");
		return;
	}

	if (activity & 0x01)
		print_field("  Suspend Page Scan");
	if (activity & 0x02)
		print_field("  Suspend Inquiry Scan");
	if (activity & 0x04)
		print_field("  Suspend Periodic Inquiries");
}

static void print_power_type(uint8_t type)
{
	const char *str;

	switch (type) {
	case 0x00:
		str = "Current Transmit Power Level";
		break;
	case 0x01:
		str = "Maximum Transmit Power Level";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Type: %s (0x%2.2x)", str, type);
}

static void print_power_level(int8_t level, const char *type)
{
	print_field("TX power%s%s%s: %d dBm",
		type ? " (" : "", type ? type : "", type ? ")" : "", level);
}

static void print_sync_flow_control(uint8_t enable)
{
	const char *str;

	switch (enable) {
	case 0x00:
		str = "Disabled";
		break;
	case 0x01:
		str = "Enabled";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Flow control: %s (0x%2.2x)", str, enable);
}

static void print_host_flow_control(uint8_t enable)
{
	const char *str;

	switch (enable) {
	case 0x00:
		str = "Off";
		break;
	case 0x01:
		str = "ACL Data Packets";
		break;
	case 0x02:
		str = "Synchronous Data Packets";
		break;
	case 0x03:
		str = "ACL and Synchronous Data Packets";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Flow control: %s (0x%2.2x)", str, enable);
}

static void print_voice_setting(uint16_t setting)
{
	uint8_t input_coding = (le16_to_cpu(setting) & 0x0300) >> 8;
	uint8_t input_data_format = (le16_to_cpu(setting) & 0xc0) >> 6;
	uint8_t air_coding_format = le16_to_cpu(setting) & 0x0003;
	const char *str;

	print_field("Setting: 0x%4.4x", le16_to_cpu(setting));

	switch (input_coding) {
	case 0x00:
		str = "Linear";
		break;
	case 0x01:
		str = "u-law";
		break;
	case 0x02:
		str = "A-law";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("  Input Coding: %s", str);

	switch (input_data_format) {
	case 0x00:
		str = "1's complement";
		break;
	case 0x01:
		str = "2's complement";
		break;
	case 0x02:
		str = "Sign-Magnitude";
		break;
	case 0x03:
		str = "Unsigned";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("  Input Data Format: %s", str);

	if (input_coding == 0x00) {
		print_field("  Input Sample Size: %s",
			le16_to_cpu(setting) & 0x20 ? "16-bit" : "8-bit");
		print_field("  # of bits padding at MSB: %d",
					(le16_to_cpu(setting) & 0x1c) >> 2);
	}

	switch (air_coding_format) {
	case 0x00:
		str = "CVSD";
		break;
	case 0x01:
		str = "u-law";
		break;
	case 0x02:
		str = "A-law";
		break;
	case 0x03:
		str = "Transparent Data";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("  Air Coding Format: %s", str);
}

static void print_retransmission_effort(uint8_t effort)
{
	const char *str;

	switch (effort) {
	case 0x00:
		str = "No retransmissions";
		break;
	case 0x01:
		str = "Optimize for power consumption";
		break;
	case 0x02:
		str = "Optimize for link quality";
		break;
	case 0xff:
		str = "Don't care";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Retransmission effort: %s (0x%2.2x)", str, effort);
}

static void print_scan_enable(uint8_t scan_enable)
{
	const char *str;

	switch (scan_enable) {
	case 0x00:
		str = "No Scans";
		break;
	case 0x01:
		str = "Inquiry Scan";
		break;
	case 0x02:
		str = "Page Scan";
		break;
	case 0x03:
		str = "Inquiry Scan + Page Scan";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Scan enable: %s (0x%2.2x)", str, scan_enable);
}

static void print_link_policy(uint16_t link_policy)
{
	uint16_t policy = le16_to_cpu(link_policy);

	print_field("Link policy: 0x%4.4x", policy);

	if (policy == 0x0000) {
		print_field("  Disable All Modes");
		return;
	}

	if (policy & 0x0001)
		print_field("  Enable Role Switch");
	if (policy & 0x0002)
		print_field("  Enable Hold Mode");
	if (policy & 0x0004)
		print_field("  Enable Sniff Mode");
	if (policy & 0x0008)
		print_field("  Enable Park State");
}

static void print_air_mode(uint8_t mode)
{
	const char *str;

	switch (mode) {
	case 0x00:
		str = "u-law log";
		break;
	case 0x01:
		str = "A-law log";
		break;
	case 0x02:
		str = "CVSD";
		break;
	case 0x03:
		str = "Transparent";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Air mode: %s (0x%2.2x)", str, mode);
}

static void print_codec(const char *label, uint8_t codec)
{
	const char *str;

	switch (codec) {
	case 0x00:
		str = "u-law log";
		break;
	case 0x01:
		str = "A-law log";
		break;
	case 0x02:
		str = "CVSD";
		break;
	case 0x03:
		str = "Transparent";
		break;
	case 0x04:
		str = "Linear PCM";
		break;
	case 0x05:
		str = "mSBC";
		break;
	case 0xff:
		str = "Vendor specific";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("%s: %s (0x%2.2x)", label, str, codec);
}

static void print_inquiry_mode(uint8_t mode)
{
	const char *str;

	switch (mode) {
	case 0x00:
		str = "Standard Inquiry Result";
		break;
	case 0x01:
		str = "Inquiry Result with RSSI";
		break;
	case 0x02:
		str = "Inquiry Result with RSSI or Extended Inquiry Result";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Mode: %s (0x%2.2x)", str, mode);
}

static void print_inquiry_scan_type(uint8_t type)
{
	const char *str;

	switch (type) {
	case 0x00:
		str = "Standard Scan";
		break;
	case 0x01:
		str = "Interlaced Scan";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Type: %s (0x%2.2x)", str, type);
}

static void print_pscan_type(uint8_t type)
{
	const char *str;

	switch (type) {
	case 0x00:
		str = "Standard Scan";
		break;
	case 0x01:
		str = "Interlaced Scan";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Type: %s (0x%2.2x)", str, type);
}

static void print_afh_mode(uint8_t mode)
{
	const char *str;

	switch (mode) {
	case 0x00:
		str = "Disabled";
		break;
	case 0x01:
		str = "Enabled";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Mode: %s (0x%2.2x)", str, mode);
}

static void print_erroneous_reporting(uint8_t mode)
{
	const char *str;

	switch (mode) {
	case 0x00:
		str = "Disabled";
		break;
	case 0x01:
		str = "Enabled";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Mode: %s (0x%2.2x)", str, mode);
}

static void print_loopback_mode(uint8_t mode)
{
	const char *str;

	switch (mode) {
	case 0x00:
		str = "No Loopback";
		break;
	case 0x01:
		str = "Local Loopback";
		break;
	case 0x02:
		str = "Remote Loopback";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Mode: %s (0x%2.2x)", str, mode);
}

static void print_simple_pairing_mode(uint8_t mode)
{
	const char *str;

	switch (mode) {
	case 0x00:
		str = "Disabled";
		break;
	case 0x01:
		str = "Enabled";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Mode: %s (0x%2.2x)", str, mode);
}

static void print_ssp_debug_mode(uint8_t mode)
{
	const char *str;

	switch (mode) {
	case 0x00:
		str = "Disabled";
		break;
	case 0x01:
		str = "Enabled";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Debug mode: %s (0x%2.2x)", str, mode);
}

static void print_secure_conn_support(uint8_t support)
{
	const char *str;

	switch (support) {
	case 0x00:
		str = "Disabled";
		break;
	case 0x01:
		str = "Enabled";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Support: %s (0x%2.2x)", str, support);
}

static void print_auth_payload_timeout(uint16_t timeout)
{
	print_field("Timeout: %d msec (0x%4.4x)",
			le16_to_cpu(timeout) * 10, le16_to_cpu(timeout));
}

static void print_pscan_rep_mode(uint8_t pscan_rep_mode)
{
	const char *str;

	switch (pscan_rep_mode) {
	case 0x00:
		str = "R0";
		break;
	case 0x01:
		str = "R1";
		break;
	case 0x02:
		str = "R2";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Page scan repetition mode: %s (0x%2.2x)",
						str, pscan_rep_mode);
}

static void print_pscan_period_mode(uint8_t pscan_period_mode)
{
	const char *str;

	switch (pscan_period_mode) {
	case 0x00:
		str = "P0";
		break;
	case 0x01:
		str = "P1";
		break;
	case 0x02:
		str = "P2";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Page period mode: %s (0x%2.2x)", str, pscan_period_mode);
}

static void print_pscan_mode(uint8_t pscan_mode)
{
	const char *str;

	switch (pscan_mode) {
	case 0x00:
		str = "Mandatory";
		break;
	case 0x01:
		str = "Optional I";
		break;
	case 0x02:
		str = "Optional II";
		break;
	case 0x03:
		str = "Optional III";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Page scan mode: %s (0x%2.2x)", str, pscan_mode);
}

static void print_clock_offset(uint16_t clock_offset)
{
	print_field("Clock offset: 0x%4.4x", le16_to_cpu(clock_offset));
}

static void print_clock(uint32_t clock)
{
	print_field("Clock: 0x%8.8x", le32_to_cpu(clock));
}

static void print_clock_type(uint8_t type)
{
	const char *str;

	switch (type) {
	case 0x00:
		str = "Local clock";
		break;
	case 0x01:
		str = "Piconet clock";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Type: %s (0x%2.2x)", str, type);
}

static void print_clock_accuracy(uint16_t accuracy)
{
	if (le16_to_cpu(accuracy) == 0xffff)
		print_field("Accuracy: Unknown (0x%4.4x)",
						le16_to_cpu(accuracy));
	else
		print_field("Accuracy: %.4f msec (0x%4.4x)",
						le16_to_cpu(accuracy) * 0.3125,
						le16_to_cpu(accuracy));
}

static void print_lpo_allowed(uint8_t lpo_allowed)
{
	print_field("LPO allowed: 0x%2.2x", lpo_allowed);
}

static void print_broadcast_fragment(uint8_t fragment)
{
	const char *str;

	switch (fragment) {
	case 0x00:
		str = "Continuation fragment";
		break;
	case 0x01:
		str = "Starting fragment";
		break;
	case 0x02:
		str = "Ending fragment";
		break;
	case 0x03:
		str = "No fragmentation";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Fragment: %s (0x%2.2x)", str, fragment);
}

static void print_link_type(uint8_t link_type)
{
	const char *str;

	switch (link_type) {
	case 0x00:
		str = "SCO";
		break;
	case 0x01:
		str = "ACL";
		break;
	case 0x02:
		str = "eSCO";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Link type: %s (0x%2.2x)", str, link_type);
}

static void print_encr_mode(uint8_t encr_mode)
{
	const char *str;

	switch (encr_mode) {
	case 0x00:
		str = "Disabled";
		break;
	case 0x01:
		str = "Enabled";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Encryption: %s (0x%2.2x)", str, encr_mode);
}

static void print_encr_mode_change(uint8_t encr_mode, uint16_t handle)
{
	const char *str;
	uint8_t conn_type;

	conn_type = get_type(le16_to_cpu(handle));

	switch (encr_mode) {
	case 0x00:
		str = "Disabled";
		break;
	case 0x01:
		switch (conn_type) {
		case 0x00:
			str = "Enabled with E0";
			break;
		case 0x01:
			str = "Enabled with AES-CCM";
			break;
		default:
			str = "Enabled";
			break;
		}
		break;
	case 0x02:
		str = "Enabled with AES-CCM";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Encryption: %s (0x%2.2x)", str, encr_mode);
}

static void print_pin_type(uint8_t pin_type)
{
	const char *str;

	switch (pin_type) {
	case 0x00:
		str = "Variable";
		break;
	case 0x01:
		str = "Fixed";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("PIN type: %s (0x%2.2x)", str, pin_type);
}

static void print_key_flag(uint8_t key_flag)
{
	const char *str;

	switch (key_flag) {
	case 0x00:
		str = "Semi-permanent";
		break;
	case 0x01:
		str = "Temporary";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Key flag: %s (0x%2.2x)", str, key_flag);
}

static void print_key_len(uint8_t key_len)
{
	const char *str;

	switch (key_len) {
	case 32:
		str = "802.11 PAL";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Key length: %s (%d)", str, key_len);
}

static void print_key_type(uint8_t key_type)
{
	const char *str;

	switch (key_type) {
	case 0x00:
		str = "Combination key";
		break;
	case 0x01:
		str = "Local Unit key";
		break;
	case 0x02:
		str = "Remote Unit key";
		break;
	case 0x03:
		str = "Debug Combination key";
		break;
	case 0x04:
		str = "Unauthenticated Combination key from P-192";
		break;
	case 0x05:
		str = "Authenticated Combination key from P-192";
		break;
	case 0x06:
		str = "Changed Combination key";
		break;
	case 0x07:
		str = "Unauthenticated Combination key from P-256";
		break;
	case 0x08:
		str = "Authenticated Combination key from P-256";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Key type: %s (0x%2.2x)", str, key_type);
}

static void print_key_size(uint8_t key_size)
{
	print_field("Key size: %d", key_size);
}

static void print_hex_field(const char *label, const uint8_t *data,
								uint8_t len)
{
	char str[len * 2 + 1];
	uint8_t i;

	str[0] = '\0';

	for (i = 0; i < len; i++)
		sprintf(str + (i * 2), "%2.2x", data[i]);

	print_field("%s: %s", label, str);
}

static void print_key(const char *label, const uint8_t *link_key)
{
	print_hex_field(label, link_key, 16);
}

static void print_link_key(const uint8_t *link_key)
{
	print_key("Link key", link_key);
}

static void print_pin_code(const uint8_t *pin_code, uint8_t pin_len)
{
	char str[pin_len + 1];
	uint8_t i;

	for (i = 0; i < pin_len; i++)
		sprintf(str + i, "%c", (const char) pin_code[i]);

	print_field("PIN code: %s", str);
}

static void print_hash_p192(const uint8_t *hash)
{
	print_key("Hash C from P-192", hash);
}

static void print_hash_p256(const uint8_t *hash)
{
	print_key("Hash C from P-256", hash);
}

static void print_randomizer_p192(const uint8_t *randomizer)
{
	print_key("Randomizer R with P-192", randomizer);
}

static void print_randomizer_p256(const uint8_t *randomizer)
{
	print_key("Randomizer R with P-256", randomizer);
}

static void print_pk256(const char *label, const uint8_t *key)
{
	print_field("%s:", label);
	print_hex_field("  X", &key[0], 32);
	print_hex_field("  Y", &key[32], 32);
}

static void print_dhkey(const uint8_t *dhkey)
{
	print_hex_field("Diffie-Hellman key", dhkey, 32);
}

static void print_passkey(uint32_t passkey)
{
	print_field("Passkey: %06d", le32_to_cpu(passkey));
}

static void print_io_capability(uint8_t capability)
{
	const char *str;

	switch (capability) {
	case 0x00:
		str = "DisplayOnly";
		break;
	case 0x01:
		str = "DisplayYesNo";
		break;
	case 0x02:
		str = "KeyboardOnly";
		break;
	case 0x03:
		str = "NoInputNoOutput";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("IO capability: %s (0x%2.2x)", str, capability);
}

static void print_oob_data(uint8_t oob_data)
{
	const char *str;

	switch (oob_data) {
	case 0x00:
		str = "Authentication data not present";
		break;
	case 0x01:
		str = "P-192 authentication data present";
		break;
	case 0x02:
		str = "P-256 authentication data present";
		break;
	case 0x03:
		str = "P-192 and P-256 authentication data present";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("OOB data: %s (0x%2.2x)", str, oob_data);
}

static void print_oob_data_response(uint8_t oob_data)
{
	const char *str;

	switch (oob_data) {
	case 0x00:
		str = "Authentication data not present";
		break;
	case 0x01:
		str = "Authentication data present";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("OOB data: %s (0x%2.2x)", str, oob_data);
}

static void print_authentication(uint8_t authentication)
{
	const char *str;

	switch (authentication) {
	case 0x00:
		str = "No Bonding - MITM not required";
		break;
	case 0x01:
		str = "No Bonding - MITM required";
		break;
	case 0x02:
		str = "Dedicated Bonding - MITM not required";
		break;
	case 0x03:
		str = "Dedicated Bonding - MITM required";
		break;
	case 0x04:
		str = "General Bonding - MITM not required";
		break;
	case 0x05:
		str = "General Bonding - MITM required";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Authentication: %s (0x%2.2x)", str, authentication);
}

static void print_location_domain_aware(uint8_t aware)
{
	const char *str;

	switch (aware) {
	case 0x00:
		str = "Regulatory domain unknown";
		break;
	case 0x01:
		str = "Regulatory domain known";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Domain aware: %s (0x%2.2x)", str, aware);
}

static void print_location_domain(const uint8_t *domain)
{
	print_field("Domain: %c%c (0x%2.2x%2.2x)",
		(char) domain[0], (char) domain[1], domain[0], domain[1]);
}

static void print_location_domain_options(uint8_t options)
{
	print_field("Domain options: %c (0x%2.2x)", (char) options, options);
}

static void print_location_options(uint8_t options)
{
	print_field("Options: 0x%2.2x", options);
}

static void print_flow_control_mode(uint8_t mode)
{
	const char *str;

	switch (mode) {
	case 0x00:
		str = "Packet based";
		break;
	case 0x01:
		str = "Data block based";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Flow control mode: %s (0x%2.2x)", str, mode);
}

static void print_flow_direction(uint8_t direction)
{
	const char *str;

	switch (direction) {
	case 0x00:
		str = "Outgoing";
		break;
	case 0x01:
		str = "Incoming";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Flow direction: %s (0x%2.2x)", str, direction);
}

static void print_service_type(uint8_t service_type)
{
	const char *str;

	switch (service_type) {
	case 0x00:
		str = "No Traffic";
		break;
	case 0x01:
		str = "Best Effort";
		break;
	case 0x02:
		str = "Guaranteed";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Service type: %s (0x%2.2x)", str, service_type);
}

static void print_flow_spec(const char *label, const uint8_t *data)
{
	const char *str;

	switch (data[1]) {
	case 0x00:
		str = "No traffic";
		break;
	case 0x01:
		str = "Best effort";
		break;
	case 0x02:
		str = "Guaranteed";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("%s flow spec: 0x%2.2x", label, data[0]);
	print_field("  Service type: %s (0x%2.2x)", str, data[1]);
	print_field("  Maximum SDU size: 0x%4.4x", get_le16(data + 2));
	print_field("  SDU inter-arrival time: 0x%8.8x", get_le32(data + 4));
	print_field("  Access latency: 0x%8.8x", get_le32(data + 8));
	print_field("  Flush timeout: 0x%8.8x", get_le32(data + 12));
}

static void print_short_range_mode(uint8_t mode)
{
	const char *str;

	switch (mode) {
	case 0x00:
		str = "Disabled";
		break;
	case 0x01:
		str = "Enabled";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Short range mode: %s (0x%2.2x)", str, mode);
}

static void print_amp_status(uint8_t amp_status)
{
	const char *str;

	switch (amp_status) {
	case 0x00:
		str = "Present";
		break;
	case 0x01:
		str = "Bluetooth only";
		break;
	case 0x02:
		str = "No capacity";
		break;
	case 0x03:
		str = "Low capacity";
		break;
	case 0x04:
		str = "Medium capacity";
		break;
	case 0x05:
		str = "High capacity";
		break;
	case 0x06:
		str = "Full capacity";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("AMP status: %s (0x%2.2x)", str, amp_status);
}

static void print_num_resp(uint8_t num_resp)
{
	print_field("Num responses: %d", num_resp);
}

static void print_num_reports(uint8_t num_reports)
{
	print_field("Num reports: %d", num_reports);
}

static void print_adv_event_type(uint8_t type)
{
	const char *str;

	switch (type) {
	case 0x00:
		str = "Connectable undirected - ADV_IND";
		break;
	case 0x01:
		str = "Connectable directed - ADV_DIRECT_IND";
		break;
	case 0x02:
		str = "Scannable undirected - ADV_SCAN_IND";
		break;
	case 0x03:
		str = "Non connectable undirected - ADV_NONCONN_IND";
		break;
	case 0x04:
		str = "Scan response - SCAN_RSP";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Event type: %s (0x%2.2x)", str, type);
}

static void print_rssi(int8_t rssi)
{
	if ((uint8_t) rssi == 0x99 || rssi == 127)
		print_field("RSSI: invalid (0x%2.2x)", (uint8_t) rssi);
	else
		print_field("RSSI: %d dBm (0x%2.2x)", rssi, (uint8_t) rssi);
}

static void print_slot_625(const char *label, uint16_t value)
{
	 print_field("%s: %.3f msec (0x%4.4x)", label,
				le16_to_cpu(value) * 0.625, le16_to_cpu(value));
}

static void print_slot_125(const char *label, uint16_t value)
{
	print_field("%s: %.2f msec (0x%4.4x)", label,
				le16_to_cpu(value) * 1.25, le16_to_cpu(value));
}

static void print_timeout(uint16_t timeout)
{
	print_slot_625("Timeout", timeout);
}

static void print_interval(uint16_t interval)
{
	print_slot_625("Interval", interval);
}

static void print_window(uint16_t window)
{
	print_slot_625("Window", window);
}

static void print_role(uint8_t role)
{
	const char *str;

	switch (role) {
	case 0x00:
		str = "Master";
		break;
	case 0x01:
		str = "Slave";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Role: %s (0x%2.2x)", str, role);
}

static void print_mode(uint8_t mode)
{
	const char *str;

	switch (mode) {
	case 0x00:
		str = "Active";
		break;
	case 0x01:
		str = "Hold";
		break;
	case 0x02:
		str = "Sniff";
		break;
	case 0x03:
		str = "Park";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Mode: %s (0x%2.2x)", str, mode);
}

static void print_name(const uint8_t *name)
{
	char str[249];

	memcpy(str, name, 248);
	str[248] = '\0';

	print_field("Name: %s", str);
}

static void print_channel_map(const uint8_t *map)
{
	unsigned int count = 0, start = 0;
	char str[21];
	int i, n;

	for (i = 0; i < 10; i++)
		sprintf(str + (i * 2), "%2.2x", map[i]);

	print_field("Channel map: 0x%s", str);

	for (i = 0; i < 10; i++) {
		for (n = 0; n < 8; n++) {
			if (map[i] & (1 << n)) {
				if (count == 0)
					start = (i * 8) + n;
				count++;
				continue;
			}

			if (count > 1) {
				print_field("  Channel %u-%u",
						start, start + count - 1);
				count = 0;
			} else if (count > 0) {
				print_field("  Channel %u", start);
				count = 0;
			}
		}
	}
}

static void print_flush_timeout(uint16_t timeout)
{
	if (timeout)
		print_timeout(timeout);
	else
		print_field("Timeout: No Automatic Flush");
}
static void print_hci_version(uint8_t version, uint16_t revision)
{
	packet_print_version("HCI version", version,
				"Revision", le16_to_cpu(revision));
}

static void print_lmp_version(uint8_t version, uint16_t subversion)
{
	packet_print_version("LMP version", version,
				"Subversion", le16_to_cpu(subversion));
}

static void print_pal_version(uint8_t version, uint16_t subversion)
{
	const char *str;

	switch (version) {
	case 0x01:
		str = "Bluetooth 3.0";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("PAL version: %s (0x%2.2x) - Subversion %d (0x%4.4x)",
						str, version,
						le16_to_cpu(subversion),
						le16_to_cpu(subversion));
}

static void print_manufacturer(uint16_t manufacturer)
{
	packet_print_company("Manufacturer", le16_to_cpu(manufacturer));
}

static const struct {
	uint16_t ver;
	const char *str;
} broadcom_uart_subversion_table[] = {
	{ 0x210b, "BCM43142A0"	},	/* 001.001.011 */
	{ 0x410e, "BCM43341B0"	},	/* 002.001.014 */
	{ 0x4406, "BCM4324B3"	},	/* 002.004.006 */
	{ }
};

static const struct {
	uint16_t ver;
	const char *str;
} broadcom_usb_subversion_table[] = {
	{ 0x210b, "BCM43142A0"	},	/* 001.001.011 */
	{ 0x2112, "BCM4314A0"	},	/* 001.001.018 */
	{ 0x2118, "BCM20702A0"	},	/* 001.001.024 */
	{ 0x2126, "BCM4335A0"	},	/* 001.001.038 */
	{ 0x220e, "BCM20702A1"	},	/* 001.002.014 */
	{ 0x230f, "BCM4354A2"	},	/* 001.003.015 */
	{ 0x4106, "BCM4335B0"	},	/* 002.001.006 */
	{ 0x410e, "BCM20702B0"	},	/* 002.001.014 */
	{ 0x6109, "BCM4335C0"	},	/* 003.001.009 */
	{ 0x610c, "BCM4354"	},	/* 003.001.012 */
	{ }
};

static void print_manufacturer_broadcom(uint16_t subversion, uint16_t revision)
{
	uint16_t ver = le16_to_cpu(subversion);
	uint16_t rev = le16_to_cpu(revision);
	const char *str = NULL;
	int i;

	switch ((rev & 0xf000) >> 12) {
	case 0:
	case 3:
		for (i = 0; broadcom_uart_subversion_table[i].str; i++) {
			if (broadcom_uart_subversion_table[i].ver == ver) {
				str = broadcom_uart_subversion_table[i].str;
				break;
			}
		}
		break;
	case 1:
	case 2:
		for (i = 0; broadcom_usb_subversion_table[i].str; i++) {
			if (broadcom_usb_subversion_table[i].ver == ver) {
				str = broadcom_usb_subversion_table[i].str;
				break;
			}
		}
		break;
	}

	if (str)
		print_field("  Firmware: %3.3u.%3.3u.%3.3u (%s)",
				(ver & 0xe000) >> 13,
				(ver & 0x1f00) >> 8, ver & 0x00ff, str);
	else
		print_field("  Firmware: %3.3u.%3.3u.%3.3u",
				(ver & 0xe000) >> 13,
				(ver & 0x1f00) >> 8, ver & 0x00ff);

	if (rev != 0xffff)
		print_field("  Build: %4.4u", rev & 0x0fff);
}

static const char *get_supported_command(int bit);

static void print_commands(const uint8_t *commands)
{
	unsigned int count = 0;
	int i, n;

	for (i = 0; i < 64; i++) {
		for (n = 0; n < 8; n++) {
			if (commands[i] & (1 << n))
				count++;
		}
	}

	print_field("Commands: %u entr%s", count, count == 1 ? "y" : "ies");

	for (i = 0; i < 64; i++) {
		for (n = 0; n < 8; n++) {
			const char *cmd;

			if (!(commands[i] & (1 << n)))
				continue;

			cmd = get_supported_command((i * 8) + n);
			if (cmd)
				print_field("  %s (Octet %d - Bit %d)",
								cmd, i, n);
			else
				print_text(COLOR_UNKNOWN_COMMAND_BIT,
						"  Octet %d - Bit %d ", i, n);
		}
	}
}

struct features_data {
	uint8_t bit;
	const char *str;
};

static const struct features_data features_page0[] = {
	{  0, "3 slot packets"				},
	{  1, "5 slot packets"				},
	{  2, "Encryption"				},
	{  3, "Slot offset"				},
	{  4, "Timing accuracy"				},
	{  5, "Role switch"				},
	{  6, "Hold mode"				},
	{  7, "Sniff mode"				},
	{  8, "Park state"				},
	{  9, "Power control requests"			},
	{ 10, "Channel quality driven data rate (CQDDR)"},
	{ 11, "SCO link"				},
	{ 12, "HV2 packets"				},
	{ 13, "HV3 packets"				},
	{ 14, "u-law log synchronous data"		},
	{ 15, "A-law log synchronous data"		},
	{ 16, "CVSD synchronous data"			},
	{ 17, "Paging parameter negotiation"		},
	{ 18, "Power control"				},
	{ 19, "Transparent synchronous data"		},
	{ 20, "Flow control lag (least significant bit)"},
	{ 21, "Flow control lag (middle bit)"		},
	{ 22, "Flow control lag (most significant bit)"	},
	{ 23, "Broadcast Encryption"			},
	{ 25, "Enhanced Data Rate ACL 2 Mbps mode"	},
	{ 26, "Enhanced Data Rate ACL 3 Mbps mode"	},
	{ 27, "Enhanced inquiry scan"			},
	{ 28, "Interlaced inquiry scan"			},
	{ 29, "Interlaced page scan"			},
	{ 30, "RSSI with inquiry results"		},
	{ 31, "Extended SCO link (EV3 packets)"		},
	{ 32, "EV4 packets"				},
	{ 33, "EV5 packets"				},
	{ 35, "AFH capable slave"			},
	{ 36, "AFH classification slave"		},
	{ 37, "BR/EDR Not Supported"			},
	{ 38, "LE Supported (Controller)"		},
	{ 39, "3-slot Enhanced Data Rate ACL packets"	},
	{ 40, "5-slot Enhanced Data Rate ACL packets"	},
	{ 41, "Sniff subrating"				},
	{ 42, "Pause encryption"			},
	{ 43, "AFH capable master"			},
	{ 44, "AFH classification master"		},
	{ 45, "Enhanced Data Rate eSCO 2 Mbps mode"	},
	{ 46, "Enhanced Data Rate eSCO 3 Mbps mode"	},
	{ 47, "3-slot Enhanced Data Rate eSCO packets"	},
	{ 48, "Extended Inquiry Response"		},
	{ 49, "Simultaneous LE and BR/EDR (Controller)"	},
	{ 51, "Secure Simple Pairing"			},
	{ 52, "Encapsulated PDU"			},
	{ 53, "Erroneous Data Reporting"		},
	{ 54, "Non-flushable Packet Boundary Flag"	},
	{ 56, "Link Supervision Timeout Changed Event"	},
	{ 57, "Inquiry TX Power Level"			},
	{ 58, "Enhanced Power Control"			},
	{ 63, "Extended features"			},
	{ }
};

static const struct features_data features_page1[] = {
	{  0, "Secure Simple Pairing (Host Support)"	},
	{  1, "LE Supported (Host)"			},
	{  2, "Simultaneous LE and BR/EDR (Host)"	},
	{  3, "Secure Connections (Host Support)"	},
	{ }
};

static const struct features_data features_page2[] = {
	{  0, "Connectionless Slave Broadcast - Master"	},
	{  1, "Connectionless Slave Broadcast - Slave"	},
	{  2, "Synchronization Train"			},
	{  3, "Synchronization Scan"			},
	{  4, "Inquiry Response Notification Event"	},
	{  5, "Generalized interlaced scan"		},
	{  6, "Coarse Clock Adjustment"			},
	{  8, "Secure Connections (Controller Support)"	},
	{  9, "Ping"					},
	{ 11, "Train nudging"				},
	{ }
};

static const struct features_data features_le[] = {
	{  0, "LE Encryption"				},
	{  1, "Connection Parameter Request Procedure"	},
	{  2, "Extended Reject Indication"		},
	{  3, "Slave-initiated Features Exchange"	},
	{  4, "LE Ping"					},
	{  5, "LE Data Packet Length Extension"		},
	{  6, "LL Privacy"				},
	{  7, "Extended Scanner Filter Policies"	},
	{ }
};

static void print_features(uint8_t page, const uint8_t *features_array,
								uint8_t type)
{
	const struct features_data *features_table = NULL;
	uint64_t mask, features = 0;
	char str[41];
	int i;

	for (i = 0; i < 8; i++) {
		sprintf(str + (i * 5), " 0x%2.2x", features_array[i]);
		features |= ((uint64_t) features_array[i]) << (i * 8);
	}

	print_field("Features:%s", str);

	switch (type) {
	case 0x00:
		switch (page) {
		case 0:
			features_table = features_page0;
			break;
		case 1:
			features_table = features_page1;
			break;
		case 2:
			features_table = features_page2;
			break;
		}
		break;
	case 0x01:
		switch (page) {
		case 0:
			features_table = features_le;
			break;
		}
		break;
	}

	if (!features_table)
		return;

	mask = features;

	for (i = 0; features_table[i].str; i++) {
		if (features & (((uint64_t) 1) << features_table[i].bit)) {
			print_field("  %s", features_table[i].str);
			mask &= ~(((uint64_t) 1) << features_table[i].bit);
		}
	}

	if (mask)
		print_text(COLOR_UNKNOWN_FEATURE_BIT, "  Unknown features "
						"(0x%16.16" PRIx64 ")", mask);
}

#define LE_STATE_SCAN_ADV		0x0001
#define LE_STATE_CONN_ADV		0x0002
#define LE_STATE_NONCONN_ADV		0x0004
#define LE_STATE_HIGH_DIRECT_ADV	0x0008
#define LE_STATE_LOW_DIRECT_ADV		0x0010
#define LE_STATE_ACTIVE_SCAN		0x0020
#define LE_STATE_PASSIVE_SCAN		0x0040
#define LE_STATE_INITIATING		0x0080
#define LE_STATE_CONN_MASTER		0x0100
#define LE_STATE_CONN_SLAVE		0x0200
#define LE_STATE_MASTER_MASTER		0x0400
#define LE_STATE_SLAVE_SLAVE		0x0800
#define LE_STATE_MASTER_SLAVE		0x1000

static const struct {
	uint8_t bit;
	const char *str;
} le_states_desc_table[] = {
	{  0, "Scannable Advertising State"			},
	{  1, "Connectable Advertising State"			},
	{  2, "Non-connectable Advertising State"		},
	{  3, "High Duty Cycle Directed Advertising State"	},
	{  4, "Low Duty Cycle Directed Advertising State"	},
	{  5, "Active Scanning State"				},
	{  6, "Passive Scanning State"				},
	{  7, "Initiating State"				},
	{  8, "Connection State (Master Role)"			},
	{  9, "Connection State (Slave Role)"			},
	{ 10, "Master Role & Master Role"			},
	{ 11, "Slave Role & Slave Role"				},
	{ 12, "Master Role & Slave Role"			},
	{ }
};

static const struct {
	uint8_t bit;
	uint16_t states;
} le_states_comb_table[] = {
	{  0, LE_STATE_NONCONN_ADV				},
	{  1, LE_STATE_SCAN_ADV					},
	{  2, LE_STATE_CONN_ADV					},
	{  3, LE_STATE_HIGH_DIRECT_ADV				},
	{  4, LE_STATE_PASSIVE_SCAN				},
	{  5, LE_STATE_ACTIVE_SCAN				},
	{  6, LE_STATE_INITIATING | LE_STATE_CONN_MASTER	},
	{  7, LE_STATE_CONN_SLAVE				},
	{  8, LE_STATE_PASSIVE_SCAN | LE_STATE_NONCONN_ADV	},
	{  9, LE_STATE_PASSIVE_SCAN | LE_STATE_SCAN_ADV		},
	{ 10, LE_STATE_PASSIVE_SCAN | LE_STATE_CONN_ADV		},
	{ 11, LE_STATE_PASSIVE_SCAN | LE_STATE_HIGH_DIRECT_ADV	},
	{ 12, LE_STATE_ACTIVE_SCAN | LE_STATE_NONCONN_ADV	},
	{ 13, LE_STATE_ACTIVE_SCAN | LE_STATE_SCAN_ADV		},
	{ 14, LE_STATE_ACTIVE_SCAN | LE_STATE_CONN_ADV		},
	{ 15, LE_STATE_ACTIVE_SCAN | LE_STATE_HIGH_DIRECT_ADV	},
	{ 16, LE_STATE_INITIATING | LE_STATE_NONCONN_ADV	},
	{ 17, LE_STATE_INITIATING | LE_STATE_SCAN_ADV		},
	{ 18, LE_STATE_CONN_MASTER | LE_STATE_NONCONN_ADV	},
	{ 19, LE_STATE_CONN_MASTER | LE_STATE_SCAN_ADV		},
	{ 20, LE_STATE_CONN_SLAVE | LE_STATE_NONCONN_ADV	},
	{ 21, LE_STATE_CONN_SLAVE | LE_STATE_SCAN_ADV		},
	{ 22, LE_STATE_INITIATING | LE_STATE_PASSIVE_SCAN	},
	{ 23, LE_STATE_INITIATING | LE_STATE_ACTIVE_SCAN	},
	{ 24, LE_STATE_CONN_MASTER | LE_STATE_PASSIVE_SCAN	},
	{ 25, LE_STATE_CONN_MASTER | LE_STATE_ACTIVE_SCAN	},
	{ 26, LE_STATE_CONN_SLAVE | LE_STATE_PASSIVE_SCAN	},
	{ 27, LE_STATE_CONN_SLAVE | LE_STATE_ACTIVE_SCAN	},
	{ 28, LE_STATE_INITIATING | LE_STATE_CONN_MASTER |
					LE_STATE_MASTER_MASTER	},
	{ 29, LE_STATE_LOW_DIRECT_ADV				},
	{ 30, LE_STATE_LOW_DIRECT_ADV | LE_STATE_PASSIVE_SCAN	},
	{ 31, LE_STATE_LOW_DIRECT_ADV | LE_STATE_ACTIVE_SCAN	},
	{ 32, LE_STATE_INITIATING | LE_STATE_CONN_ADV |
					LE_STATE_MASTER_SLAVE	},
	{ 33, LE_STATE_INITIATING | LE_STATE_HIGH_DIRECT_ADV |
					LE_STATE_MASTER_SLAVE	},
	{ 34, LE_STATE_INITIATING | LE_STATE_LOW_DIRECT_ADV |
					LE_STATE_MASTER_SLAVE	},
	{ 35, LE_STATE_CONN_MASTER | LE_STATE_CONN_ADV |
					LE_STATE_MASTER_SLAVE	},
	{ 36, LE_STATE_CONN_MASTER | LE_STATE_HIGH_DIRECT_ADV |
					LE_STATE_MASTER_SLAVE	},
	{ 37, LE_STATE_CONN_MASTER | LE_STATE_LOW_DIRECT_ADV |
					LE_STATE_MASTER_SLAVE	},
	{ 38, LE_STATE_CONN_SLAVE | LE_STATE_CONN_ADV |
					LE_STATE_MASTER_SLAVE	},
	{ 39, LE_STATE_CONN_SLAVE | LE_STATE_HIGH_DIRECT_ADV |
					LE_STATE_SLAVE_SLAVE	},
	{ 40, LE_STATE_CONN_SLAVE | LE_STATE_LOW_DIRECT_ADV |
					LE_STATE_SLAVE_SLAVE	},
	{ 41, LE_STATE_INITIATING | LE_STATE_CONN_SLAVE |
					LE_STATE_MASTER_SLAVE	},
	{ }
};

static void print_le_states(const uint8_t *states_array)
{
	uint64_t mask, states = 0;
	int i, n;

	for (i = 0; i < 8; i++)
		states |= ((uint64_t) states_array[i]) << (i * 8);

	print_field("States: 0x%16.16" PRIx64, states);

	mask = states;

	for (i = 0; le_states_comb_table[i].states; i++) {
		uint64_t val = (((uint64_t) 1) << le_states_comb_table[i].bit);
		const char *str[3] = { NULL, };
		int num = 0;

		if (!(states & val))
			continue;

		for (n = 0; n < 16; n++) {
			if (le_states_comb_table[i].states & (1 << n))
				str[num++] = le_states_desc_table[n].str;
		}

		if (num > 0) {
			print_field("  %s", str[0]);
			for (n = 1; n < num; n++)
				print_field("    and %s", str[n]);
		}

		mask &= ~val;
	}

	if (mask)
		print_text(COLOR_UNKNOWN_LE_STATES, "  Unknown states "
						"(0x%16.16" PRIx64 ")", mask);
}

static void print_le_channel_map(const uint8_t *map)
{
	unsigned int count = 0, start = 0;
	char str[11];
	int i, n;

	for (i = 0; i < 5; i++)
		sprintf(str + (i * 2), "%2.2x", map[i]);

	print_field("Channel map: 0x%s", str);

	for (i = 0; i < 5; i++) {
		for (n = 0; n < 8; n++) {
			if (map[i] & (1 << n)) {
				if (count == 0)
					start = (i * 8) + n;
				count++;
				continue;
			}

			if (count > 1) {
				print_field("  Channel %u-%u",
						start, start + count - 1);
				count = 0;
			} else if (count > 0) {
				print_field("  Channel %u", start);
				count = 0;
			}
		}
	}
}

static void print_random_number(uint64_t rand)
{
	print_field("Random number: 0x%16.16" PRIx64, le64_to_cpu(rand));
}

static void print_encrypted_diversifier(uint16_t ediv)
{
	print_field("Encrypted diversifier: 0x%4.4x", le16_to_cpu(ediv));
}

static const struct {
	uint8_t bit;
	const char *str;
} events_table[] = {
	{  0, "Inquiry Complete"					},
	{  1, "Inquiry Result"						},
	{  2, "Connection Complete"					},
	{  3, "Connection Request"					},
	{  4, "Disconnection Complete"					},
	{  5, "Authentication Complete"					},
	{  6, "Remote Name Request Complete"				},
	{  7, "Encryption Change"					},
	{  8, "Change Connection Link Key Complete"			},
	{  9, "Master Link Key Complete"				},
	{ 10, "Read Remote Supported Features Complete"			},
	{ 11, "Read Remote Version Information Complete"		},
	{ 12, "QoS Setup Complete"					},
	{ 13, "Command Complete"					},
	{ 14, "Command Status"						},
	{ 15, "Hardware Error"						},
	{ 16, "Flush Occurred"						},
	{ 17, "Role Change"						},
	{ 18, "Number of Completed Packets"				},
	{ 19, "Mode Change"						},
	{ 20, "Return Link Keys"					},
	{ 21, "PIN Code Request"					},
	{ 22, "Link Key Request"					},
	{ 23, "Link Key Notification"					},
	{ 24, "Loopback Command"					},
	{ 25, "Data Buffer Overflow"					},
	{ 26, "Max Slots Change"					},
	{ 27, "Read Clock Offset Complete"				},
	{ 28, "Connection Packet Type Changed"				},
	{ 29, "QoS Violation"						},
	{ 30, "Page Scan Mode Change"					},
	{ 31, "Page Scan Repetition Mode Change"			},
	{ 32, "Flow Specification Complete"				},
	{ 33, "Inquiry Result with RSSI"				},
	{ 34, "Read Remote Extended Features Complete"			},
	{ 43, "Synchronous Connection Complete"				},
	{ 44, "Synchronous Connection Changed"				},
	{ 45, "Sniff Subrating"						},
	{ 46, "Extended Inquiry Result"					},
	{ 47, "Encryption Key Refresh Complete"				},
	{ 48, "IO Capability Request"					},
	{ 49, "IO Capability Request Reply"				},
	{ 50, "User Confirmation Request"				},
	{ 51, "User Passkey Request"					},
	{ 52, "Remote OOB Data Request"					},
	{ 53, "Simple Pairing Complete"					},
	{ 55, "Link Supervision Timeout Changed"			},
	{ 56, "Enhanced Flush Complete"					},
	{ 58, "User Passkey Notification"				},
	{ 59, "Keypress Notification"					},
	{ 60, "Remote Host Supported Features Notification"		},
	{ 61, "LE Meta"							},
	{ }
};

static void print_event_mask(const uint8_t *events_array)
{
	uint64_t mask, events = 0;
	int i;

	for (i = 0; i < 8; i++)
		events |= ((uint64_t) events_array[i]) << (i * 8);

	print_field("Mask: 0x%16.16" PRIx64, events);

	mask = events;

	for (i = 0; events_table[i].str; i++) {
		if (events & (((uint64_t) 1) << events_table[i].bit)) {
			print_field("  %s", events_table[i].str);
			mask &= ~(((uint64_t) 1) << events_table[i].bit);
		}
	}

	if (mask)
		print_text(COLOR_UNKNOWN_EVENT_MASK, "  Unknown mask "
						"(0x%16.16" PRIx64 ")", mask);
}

static const struct {
	uint8_t bit;
	const char *str;
} events_page2_table[] = {
	{  0, "Physical Link Complete"					},
	{  1, "Channel Selected"					},
	{  2, "Disconnection Physical Link Complete"			},
	{  3, "Physical Link Loss Early Warning"			},
	{  4, "Physical Link Recovery"					},
	{  5, "Logical Link Complete"					},
	{  6, "Disconnection Logical Link Complete"			},
	{  7, "Flow Specification Modify Complete"			},
	{  8, "Number of Completed Data Blocks"				},
	{  9, "AMP Start Test"						},
	{ 10, "AMP Test End"						},
	{ 11, "AMP Receiver Report"					},
	{ 12, "Short Range Mode Change Complete"			},
	{ 13, "AMP Status Change"					},
	{ 14, "Triggered Clock Capture"					},
	{ 15, "Synchronization Train Complete"				},
	{ 16, "Synchronization Train Received"				},
	{ 17, "Connectionless Slave Broadcast Receive"			},
	{ 18, "Connectionless Slave Broadcast Timeout"			},
	{ 19, "Truncated Page Complete"					},
	{ 20, "Slave Page Response Timeout"				},
	{ 21, "Connectionless Slave Broadcast Channel Map Change"	},
	{ 22, "Inquiry Response Notification"				},
	{ 23, "Authenticated Payload Timeout Expired"			},
	{ }
};

static void print_event_mask_page2(const uint8_t *events_array)
{
	uint64_t mask, events = 0;
	int i;

	for (i = 0; i < 8; i++)
		events |= ((uint64_t) events_array[i]) << (i * 8);

	print_field("Mask: 0x%16.16" PRIx64, events);

	mask = events;

	for (i = 0; events_page2_table[i].str; i++) {
		if (events & (((uint64_t) 1) << events_page2_table[i].bit)) {
			print_field("  %s", events_page2_table[i].str);
			mask &= ~(((uint64_t) 1) << events_page2_table[i].bit);
		}
	}

	if (mask)
		print_text(COLOR_UNKNOWN_EVENT_MASK, "  Unknown mask "
						"(0x%16.16" PRIx64 ")", mask);
}

static const struct {
	uint8_t bit;
	const char *str;
} events_le_table[] = {
	{  0, "LE Connection Complete"			},
	{  1, "LE Advertising Report"			},
	{  2, "LE Connection Update Complete"		},
	{  3, "LE Read Remote Used Features Complete"	},
	{  4, "LE Long Term Key Request"		},
	{  5, "LE Remote Connection Parameter Request"	},
	{  6, "LE Data Length Change"			},
	{  7, "LE Read Local P-256 Public Key Complete"	},
	{  8, "LE Generate DHKey Complete"		},
	{  9, "LE Enhanced Connection Complete"		},
	{ 10, "LE Direct Advertising Report"		},
	{ }
};

static void print_event_mask_le(const uint8_t *events_array)
{
	uint64_t mask, events = 0;
	int i;

	for (i = 0; i < 8; i++)
		events |= ((uint64_t) events_array[i]) << (i * 8);

	print_field("Mask: 0x%16.16" PRIx64, events);

	mask = events;

	for (i = 0; events_le_table[i].str; i++) {
		if (events & (((uint64_t) 1) << events_le_table[i].bit)) {
			print_field("  %s", events_le_table[i].str);
			mask &= ~(((uint64_t) 1) << events_le_table[i].bit);
		}
	}

	if (mask)
		print_text(COLOR_UNKNOWN_EVENT_MASK, "  Unknown mask "
						"(0x%16.16" PRIx64 ")", mask);
}

static void print_fec(uint8_t fec)
{
	const char *str;

	switch (fec) {
	case 0x00:
		str = "Not required";
		break;
	case 0x01:
		str = "Required";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("FEC: %s (0x%02x)", str, fec);
}

#define BT_EIR_FLAGS			0x01
#define BT_EIR_UUID16_SOME		0x02
#define BT_EIR_UUID16_ALL		0x03
#define BT_EIR_UUID32_SOME		0x04
#define BT_EIR_UUID32_ALL		0x05
#define BT_EIR_UUID128_SOME		0x06
#define BT_EIR_UUID128_ALL		0x07
#define BT_EIR_NAME_SHORT		0x08
#define BT_EIR_NAME_COMPLETE		0x09
#define BT_EIR_TX_POWER			0x0a
#define BT_EIR_CLASS_OF_DEV		0x0d
#define BT_EIR_SSP_HASH_P192		0x0e
#define BT_EIR_SSP_RANDOMIZER_P192	0x0f
#define BT_EIR_DEVICE_ID		0x10
#define BT_EIR_SMP_TK			0x10
#define BT_EIR_SMP_OOB_FLAGS		0x11
#define BT_EIR_SLAVE_CONN_INTERVAL	0x12
#define BT_EIR_SERVICE_UUID16		0x14
#define BT_EIR_SERVICE_UUID128		0x15
#define BT_EIR_SERVICE_DATA		0x16
#define BT_EIR_PUBLIC_ADDRESS		0x17
#define BT_EIR_RANDOM_ADDRESS		0x18
#define BT_EIR_GAP_APPEARANCE		0x19
#define BT_EIR_ADVERTISING_INTERVAL	0x1a
#define BT_EIR_LE_DEVICE_ADDRESS	0x1b
#define BT_EIR_LE_ROLE			0x1c
#define BT_EIR_SSP_HASH_P256		0x1d
#define BT_EIR_SSP_RANDOMIZER_P256	0x1e
#define BT_EIR_3D_INFO_DATA		0x3d
#define BT_EIR_MANUFACTURER_DATA	0xff

static void print_manufacturer_apple(const void *data, uint8_t data_len)
{
	uint8_t type = *((uint8_t *) data);

	if (data_len < 1)
		return;

	if (type == 0x01) {
		char identifier[100];

		snprintf(identifier, sizeof(identifier) - 1, "%s",
						(const char *) (data + 1));

		print_field("  Identifier: %s", identifier);
		return;
	}

	while (data_len > 0) {
		uint8_t len;
		const char *str;

		type = *((uint8_t *) data);
		data++;
		data_len--;

		if (type == 0x00)
			continue;

		if (data_len < 1)
			break;

		switch (type) {
		case 0x02:
			str = "iBeacon";
			break;
		case 0x05:
			str = "AirDrop";
			break;
		case 0x09:
			str = "Apple TV";
			break;
		default:
			str = "Unknown";
			break;
		}

		print_field("  Type: %s (%u)", str, type);

		len = *((uint8_t *) data);
		data++;
		data_len--;

		if (len < 1)
			continue;

		if (len > data_len)
			break;

		if (type == 0x02 && len == 0x15) {
			const uint8_t *uuid;
			uint16_t minor, major;
			int8_t tx_power;

			uuid = data;
			print_field("  UUID: %8.8x-%4.4x-%4.4x-%4.4x-%8.8x%4.4x",
				get_le32(&uuid[12]), get_le16(&uuid[10]),
				get_le16(&uuid[8]), get_le16(&uuid[6]),
				get_le32(&uuid[2]), get_le16(&uuid[0]));

			major = get_le16(data + 16);
			minor = get_le16(data + 18);
			print_field("  Version: %u.%u", major, minor);

			tx_power = *(int8_t *) (data + 20);
			print_field("  TX power: %d dB", tx_power);
		} else
			print_hex_field("  Data", data, len);

		data += len;
		data_len -= len;
	}

	packet_hexdump(data, data_len);
}

static void print_manufacturer_data(const void *data, uint8_t data_len)
{
	uint16_t company = get_le16(data);

	packet_print_company("Company", company);

	switch (company) {
	case 76:
	case 19456:
		print_manufacturer_apple(data + 2, data_len - 2);
		break;
	default:
		print_hex_field("  Data", data + 2, data_len - 2);
		break;
	}
}

static void print_device_id(const void *data, uint8_t data_len)
{
	uint16_t source, vendor, product, version;
	char modalias[26], *vendor_str, *product_str;
	const char *str;

	if (data_len < 8)
		return;

	source = get_le16(data);
	vendor = get_le16(data + 2);
	product = get_le16(data + 4);
	version = get_le16(data + 6);

	switch (source) {
	case 0x0001:
		str = "Bluetooth SIG assigned";
		sprintf(modalias, "bluetooth:v%04Xp%04Xd%04X",
						vendor, product, version);
		break;
	case 0x0002:
		str = "USB Implementer's Forum assigned";
		sprintf(modalias, "usb:v%04Xp%04Xd%04X",
						vendor, product, version);
		break;
	default:
		str = "Reserved";
		modalias[0] = '\0';
		break;
	}

	print_field("Device ID: %s (0x%4.4x)", str, source);

	if (!hwdb_get_vendor_model(modalias, &vendor_str, &product_str)) {
		vendor_str = NULL;
		product_str = NULL;
	}

	if (source != 0x0001) {
		if (vendor_str)
			print_field("  Vendor: %s (0x%4.4x)",
						vendor_str, vendor);
		else
			print_field("  Vendor: 0x%4.4x", vendor);
	} else
		packet_print_company("  Vendor", vendor);

	if (product_str)
		print_field("  Product: %s (0x%4.4x)", product_str, product);
	else
		print_field("  Product: 0x%4.4x", product);

	print_field("  Version: %u.%u.%u (0x%4.4x)",
					(version & 0xff00) >> 8,
					(version & 0x00f0) >> 4,
					(version & 0x000f), version);

	free(vendor_str);
	free(product_str);
}

static void print_uuid16_list(const char *label, const void *data,
							uint8_t data_len)
{
	uint8_t count = data_len / sizeof(uint16_t);
	unsigned int i;

	print_field("%s: %u entr%s", label, count, count == 1 ? "y" : "ies");

	for (i = 0; i < count; i++) {
		uint16_t uuid = get_le16(data + (i * 2));
		print_field("  %s (0x%4.4x)", uuid16_to_str(uuid), uuid);
	}
}

static void print_uuid32_list(const char *label, const void *data,
							uint8_t data_len)
{
	uint8_t count = data_len / sizeof(uint32_t);
	unsigned int i;

	print_field("%s: %u entr%s", label, count, count == 1 ? "y" : "ies");

	for (i = 0; i < count; i++) {
		uint32_t uuid = get_le32(data + (i * 4));
		print_field("  %s (0x%8.8x)", uuid32_to_str(uuid), uuid);
	}
}

static void print_uuid128_list(const char *label, const void *data,
							uint8_t data_len)
{
	uint8_t count = data_len / 16;
	unsigned int i;

	print_field("%s: %u entr%s", label, count, count == 1 ? "y" : "ies");

	for (i = 0; i < count; i++) {
		const uint8_t *uuid = data + (i * 16);

		print_field("  %8.8x-%4.4x-%4.4x-%4.4x-%8.8x%4.4x",
				get_le32(&uuid[12]), get_le16(&uuid[10]),
				get_le16(&uuid[8]), get_le16(&uuid[6]),
				get_le32(&uuid[2]), get_le16(&uuid[0]));
	}
}

static const struct {
	uint8_t bit;
	const char *str;
} eir_flags_table[] = {
	{ 0, "LE Limited Discoverable Mode"		},
	{ 1, "LE General Discoverable Mode"		},
	{ 2, "BR/EDR Not Supported"			},
	{ 3, "Simultaneous LE and BR/EDR (Controller)"	},
	{ 4, "Simultaneous LE and BR/EDR (Host)"	},
	{ }
};

static const struct {
	uint8_t bit;
	const char *str;
} eir_3d_table[] = {
	{ 0, "Association Notification"					},
	{ 1, "Battery Level Reporting"					},
	{ 2, "Send Battery Level Report on Start-up Synchronization"	},
	{ 7, "Factory Test Mode"					},
	{ }
};

static void print_eir(const uint8_t *eir, uint8_t eir_len, bool le)
{
	uint16_t len = 0;

	if (eir_len == 0)
		return;

	while (len < eir_len - 1) {
		uint8_t field_len = eir[0];
		const uint8_t *data = &eir[2];
		uint8_t data_len;
		char name[239], label[100];
		uint8_t flags, mask;
		int i;

		/* Check for the end of EIR */
		if (field_len == 0)
			break;

		len += field_len + 1;

		/* Do not continue EIR Data parsing if got incorrect length */
		if (len > eir_len) {
			len -= field_len + 1;
			break;
		}

		data_len = field_len - 1;

		switch (eir[1]) {
		case BT_EIR_FLAGS:
			flags = *data;
			mask = flags;

			print_field("Flags: 0x%2.2x", flags);

			for (i = 0; eir_flags_table[i].str; i++) {
				if (flags & (1 << eir_flags_table[i].bit)) {
					print_field("  %s",
							eir_flags_table[i].str);
					mask &= ~(1 << eir_flags_table[i].bit);
				}
			}

			if (mask)
				print_text(COLOR_UNKNOWN_SERVICE_CLASS,
					"  Unknown flags (0x%2.2x)", mask);
			break;

		case BT_EIR_UUID16_SOME:
			if (data_len < sizeof(uint16_t))
				break;
			print_uuid16_list("16-bit Service UUIDs (partial)",
							data, data_len);
			break;

		case BT_EIR_UUID16_ALL:
			if (data_len < sizeof(uint16_t))
				break;
			print_uuid16_list("16-bit Service UUIDs (complete)",
							data, data_len);
			break;

		case BT_EIR_UUID32_SOME:
			if (data_len < sizeof(uint32_t))
				break;
			print_uuid32_list("32-bit Service UUIDs (partial)",
							data, data_len);
			break;

		case BT_EIR_UUID32_ALL:
			if (data_len < sizeof(uint32_t))
				break;
			print_uuid32_list("32-bit Service UUIDs (complete)",
							data, data_len);
			break;

		case BT_EIR_UUID128_SOME:
			if (data_len < 16)
				break;
			print_uuid128_list("128-bit Service UUIDs (partial)",
								data, data_len);
			break;

		case BT_EIR_UUID128_ALL:
			if (data_len < 16)
				break;
			print_uuid128_list("128-bit Service UUIDs (complete)",
								data, data_len);
			break;

		case BT_EIR_NAME_SHORT:
			memset(name, 0, sizeof(name));
			memcpy(name, data, data_len);
			print_field("Name (short): %s", name);
			break;

		case BT_EIR_NAME_COMPLETE:
			memset(name, 0, sizeof(name));
			memcpy(name, data, data_len);
			print_field("Name (complete): %s", name);
			break;

		case BT_EIR_TX_POWER:
			if (data_len < 1)
				break;
			print_field("TX power: %d dBm", (int8_t) *data);
			break;

		case BT_EIR_CLASS_OF_DEV:
			if (data_len < 3)
				break;
			print_dev_class(data);
			break;

		case BT_EIR_SSP_HASH_P192:
			if (data_len < 16)
				break;
			print_hash_p192(data);
			break;

		case BT_EIR_SSP_RANDOMIZER_P192:
			if (data_len < 16)
				break;
			print_randomizer_p192(data);
			break;

		case BT_EIR_DEVICE_ID:
			/* SMP TK has the same value as Device ID */
			if (le)
				print_hex_field("SMP TK", data, data_len);
			else if (data_len >= 8)
				print_device_id(data, data_len);
			break;

		case BT_EIR_SMP_OOB_FLAGS:
			print_field("SMP OOB Flags: 0x%2.2x", *data);
			break;

		case BT_EIR_SLAVE_CONN_INTERVAL:
			if (data_len < 4)
				break;
			print_field("Slave Conn. Interval: 0x%4.4x - 0x%4.4x",
							get_le16(&data[0]),
							get_le16(&data[2]));
			break;

		case BT_EIR_SERVICE_UUID16:
			if (data_len < sizeof(uint16_t))
				break;
			print_uuid16_list("16-bit Service UUIDs",
							data, data_len);
			break;

		case BT_EIR_SERVICE_UUID128:
			if (data_len < 16)
				break;
			print_uuid128_list("128-bit Service UUIDs",
							data, data_len);
			break;

		case BT_EIR_SERVICE_DATA:
			if (data_len < 2)
				break;
			sprintf(label, "Service Data (UUID 0x%4.4x)",
							get_le16(&data[0]));
			print_hex_field(label, &data[2], data_len - 2);
			break;

		case BT_EIR_RANDOM_ADDRESS:
			if (data_len < 6)
				break;
			print_addr("Random Address", data, 0x01);
			break;

		case BT_EIR_PUBLIC_ADDRESS:
			if (data_len < 6)
				break;
			print_addr("Public Address", data, 0x00);
			break;

		case BT_EIR_GAP_APPEARANCE:
			if (data_len < 2)
				break;
			print_appearance(get_le16(data));
			break;

		case BT_EIR_SSP_HASH_P256:
			if (data_len < 16)
				break;
			print_hash_p256(data);
			break;

		case BT_EIR_SSP_RANDOMIZER_P256:
			if (data_len < 16)
				break;
			print_randomizer_p256(data);
			break;

		case BT_EIR_3D_INFO_DATA:
			print_hex_field("3D Information Data", data, data_len);
			if (data_len < 2)
				break;

			flags = *data;
			mask = flags;

			print_field("  Features: 0x%2.2x", flags);

			for (i = 0; eir_3d_table[i].str; i++) {
				if (flags & (1 << eir_3d_table[i].bit)) {
					print_field("    %s",
							eir_3d_table[i].str);
					mask &= ~(1 << eir_3d_table[i].bit);
				}
			}

			if (mask)
				print_text(COLOR_UNKNOWN_FEATURE_BIT,
					"      Unknown features (0x%2.2x)", mask);

			print_field("  Path Loss Threshold: %d", data[1]);
			break;

		case BT_EIR_MANUFACTURER_DATA:
			if (data_len < 2)
				break;
			print_manufacturer_data(data, data_len);
			break;

		default:
			sprintf(label, "Unknown EIR field 0x%2.2x", eir[1]);
			print_hex_field(label, data, data_len);
			break;
		}

		eir += field_len + 1;
	}

	if (len < eir_len && eir[0] != 0)
		packet_hexdump(eir, eir_len - len);
}

void packet_print_addr(const char *label, const void *data, bool random)
{
	print_addr(label ? : "Address", data, random ? 0x01 : 0x00);
}

void packet_print_ad(const void *data, uint8_t size)
{
	print_eir(data, size, true);
}

struct broadcast_message {
	uint32_t frame_sync_instant;
	uint16_t bluetooth_clock_phase;
	uint16_t left_open_offset;
	uint16_t left_close_offset;
	uint16_t right_open_offset;
	uint16_t right_close_offset;
	uint16_t frame_sync_period;
	uint8_t  frame_sync_period_fraction;
} __attribute__ ((packed));

static void print_3d_broadcast(const void *data, uint8_t size)
{
	const struct broadcast_message *msg = data;
	uint32_t instant;
	uint16_t left_open, left_close, right_open, right_close;
	uint16_t phase, period;
	uint8_t period_frac;
	bool mode;

	instant = le32_to_cpu(msg->frame_sync_instant);
	mode = !!(instant & 0x40000000);
	phase = le16_to_cpu(msg->bluetooth_clock_phase);
	left_open = le16_to_cpu(msg->left_open_offset);
	left_close = le16_to_cpu(msg->left_close_offset);
	right_open = le16_to_cpu(msg->right_open_offset);
	right_close = le16_to_cpu(msg->right_close_offset);
	period = le16_to_cpu(msg->frame_sync_period);
	period_frac = msg->frame_sync_period_fraction;

	print_field("  Frame sync instant: 0x%8.8x", instant & 0x7fffffff);
	print_field("  Video mode: %s (%d)", mode ? "Dual View" : "3D", mode);
	print_field("  Bluetooth clock phase: %d usec (0x%4.4x)",
						phase, phase);
	print_field("  Left lense shutter open offset: %d usec (0x%4.4x)",
						left_open, left_open);
	print_field("  Left lense shutter close offset: %d usec (0x%4.4x)",
						left_close, left_close);
	print_field("  Right lense shutter open offset: %d usec (0x%4.4x)",
						right_open, right_open);
	print_field("  Right lense shutter close offset: %d usec (0x%4.4x)",
						right_close, right_close);
	print_field("  Frame sync period: %d.%d usec (0x%4.4x 0x%2.2x)",
						period, period_frac * 256,
						period, period_frac);
}

void packet_hexdump(const unsigned char *buf, uint16_t len)
{
	static const char hexdigits[] = "0123456789abcdef";
	char str[68];
	uint16_t i;

	if (!len)
		return;

	for (i = 0; i < len; i++) {
		str[((i % 16) * 3) + 0] = hexdigits[buf[i] >> 4];
		str[((i % 16) * 3) + 1] = hexdigits[buf[i] & 0xf];
		str[((i % 16) * 3) + 2] = ' ';
		str[(i % 16) + 49] = isprint(buf[i]) ? buf[i] : '.';

		if ((i + 1) % 16 == 0) {
			str[47] = ' ';
			str[48] = ' ';
			str[65] = '\0';
			print_text(COLOR_WHITE, "%s", str);
			str[0] = ' ';
		}
	}

	if (i % 16 > 0) {
		uint16_t j;
		for (j = (i % 16); j < 16; j++) {
			str[(j * 3) + 0] = ' ';
			str[(j * 3) + 1] = ' ';
			str[(j * 3) + 2] = ' ';
			str[j + 49] = ' ';
		}
		str[47] = ' ';
		str[48] = ' ';
		str[65] = '\0';
		print_text(COLOR_WHITE, "%s", str);
	}
}

static int addr2str(const uint8_t *addr, char *str)
{
	return sprintf(str, "%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X",
			addr[5], addr[4], addr[3], addr[2], addr[1], addr[0]);
}
static void le_adv_report_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_le_adv_report *evt = data;
	uint8_t evt_len;
	int8_t *rssi;

	print_num_reports(evt->num_reports);

report:
	print_adv_event_type(evt->event_type);
	print_peer_addr_type("Address type", evt->addr_type);
	print_addr("Address", evt->addr, evt->addr_type);
	print_field("Data length: %d", evt->data_len);
	print_eir(evt->data, evt->data_len, true);

	rssi = (int8_t *) (evt->data + evt->data_len);
	print_rssi(*rssi);

	evt_len = sizeof(*evt) + evt->data_len + 1;

	if (size > evt_len) {
		data += evt_len - 1;
		size -= evt_len - 1;
		evt = data;
		goto report;
	}
}


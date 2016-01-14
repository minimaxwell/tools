# MMC tools
Small tools for use with MMC devices

# read\_ext\_csd ext\_csd\_file offset nb\_bytes

Reads the 'nb\_bytes" bytes from offset "offset" in file "ext\_csd\_file".
This file is located in debugfs and contains a dump of extended CSD registers.
( often /sys/kernel/debug/mmc/mmcX/mmcX:0001/ext\_csd )

# write\_ext\_csd

Sets a value "value" in offset "offset" in extended CSD registers. By default
performs action on /dev/mmcblk0 device. Uses the ioctl interface to send a CMD6
 ( SWITCH ) to set the ECSD register value.

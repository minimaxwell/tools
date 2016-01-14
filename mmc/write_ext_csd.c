/*Copyright (c) 2016 Maxime Chevallier
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.*/

/* Sets an extended CSD register in emmc.
 * Usage : ./write_ext_csd REGISTER VALUE 
 * Uses CMD6 'SWITCH' to set the register */

#include <stdio.h>
#include <fcntl.h>
#include <linux/mmc/ioctl.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#define MMC_BLOCK_MAJOR 179
#define MMC_RSP_R1B ((1 << 0) | (1 << 2) | (1 << 4) | (1 << 3))
#define MMC_IOC_CMD_RESET _IO(MMC_BLOCK_MAJOR, 0)

#define ECSD_ACCESS 0x3
#define ECSD_CMD_SET 0

int get_fd(){
	int fd;

	fd = open("/dev/mmcblk0", O_RDWR|O_NONBLOCK);
	if(!fd)
		printf("%s : could not open /dev/mmcblk0\n", __func__);

	return fd;
}

int send_cmd(int fd, struct mmc_ioc_cmd *cmd){
	int ret;

	ret = ioctl(fd, MMC_IOC_CMD, cmd);
	printf("%s : CMD%d : ret=%d\n", __func__,  cmd->opcode, ret);
	if(errno)
		printf("errno : %s\n", strerror(errno));
	printf("response : %08x %08x %08x %08x\n", 
			cmd->response[0], cmd->response[1], 
			cmd->response[2], cmd->response[3]);
	return ret;
}

inline int build_cmd6_args(int cmd_set, int value, int index, int access){
	int args = 0;

	args = 	(cmd_set & 0x7) |
			((value & 0xFF) << 8) |
			((index & 0xFF) << 16) |
			((access & 0x3) << 24);

	return args;
}


int set_ext_csd(int fd, int offset, int value){

	int ret = 0;
	int args = 0;
	struct mmc_ioc_cmd cmd;
	memset(&cmd, 0, sizeof(struct mmc_ioc_cmd));

	/* Build CMD6 SWITCH to set an ext_csd value */
	cmd.write_flag = 1;
	cmd.opcode = 6; //CMD6 : SWITCH
	cmd.arg = build_cmd6_args(ECSD_CMD_SET, value, offset, ECSD_ACCESS);
	cmd.flags = 0x049d; // MMC_RSP_SPI_R1B | MMC_RSP_R1B | MMC_CMD_AC

	ret = send_cmd(fd, &cmd);

	return ret;
}

int main(int argc, char **argv){
	int ret = 0;
	int fd = 0;
	unsigned int offset = 0;
	unsigned int value = 0;

	if(argc != 3){
		printf("Usage : write_ext_csd offset value\n");
		return 1;
	}

	sscanf(argv[1],"%u", &offset);
	sscanf(argv[2],"%u", &value);

	fd = get_fd();

	if(fd){
		ret = set_ext_csd(fd, offset, value);
		close(fd);
	}

	return ret;
}

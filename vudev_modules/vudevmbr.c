/*
 *   VUOS: view OS project
 *   Copyright (C) 2018  Renzo Davoli <renzo@cs.unibo.it>
 *   with contributions by Alessio Volpe <alessio.volpe3@studio.unibo.it>
 *   VirtualSquare team.
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <endian.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include <linux/hdreg.h>

#include <vudev.h>
#include <vumodule.h>


#include <linux/blkpg.h>
#include <linux/fs.h>

#define IDE_BLOCKSIZE 512
#define IDE_BLOCKSIZE_LOG 9
#define IDE_HEADER_OFFSET 446

#define PART_ADDRBASE(partition) (((off_t) partition->LBAbegin) << IDE_BLOCKSIZE_LOG)
#define PART_ADDRMAX(partition) (((off_t) partition->LBAnoblocks) << IDE_BLOCKSIZE_LOG)

struct vupartition_t {
	uint8_t bootflag;
  uint8_t type;
  uint8_t readonly;
  uint64_t LBAbegin;
  uint64_t LBAnoblocks;
};

struct vumbr_t {
	int fd;
  off_t size;
  int part_table_last_elem;
  struct vupartition_t *part_table;
};

struct vumbrfd_t {
  off_t offset;
  struct vupartition_t *partition;
};

/******************************************************************************/
/************************************UTILS*************************************/

static int _read_mbr(int fd, off_t size, struct  vupartition_t *part_table, int maxpart) {
  uint8_t vumbr_signature[2] = {0x55, 0xAA};
  uint32_t ext_part_base = 0;
  struct {
    uint8_t code[IDE_HEADER_OFFSET];
    struct {
      uint8_t bootflag;
      uint8_t chs_begin[3];
      uint8_t type;
      uint8_t chs_end[3];
      uint32_t lba_begin;
      uint32_t lba_noblocks;
    } vumbrpart[4] __attribute__((__packed__));
    uint8_t signature[2];
  } vumbr_header;
  pread64(fd, &vumbr_header, sizeof(vumbr_header), (off_t) 0);
  if (part_table) {
    part_table[0].LBAnoblocks = (size >> IDE_BLOCKSIZE_LOG);
    part_table[0].type = 0xff;
    part_table[0].readonly = 0;
    part_table[0].bootflag = 0;
  }
  if(memcmp(vumbr_header.signature, vumbr_signature, 2) != 0) {
		if (part_table) /* avoid double warning */
			printk(KERN_ERR "Bad signature in vumbr %x %x\n", vumbr_header.signature[0], vumbr_header.signature[1]);
    return 0;
  }
  /* MBR is okay. Read MBR */
  int i, part_table_last_elem = 4;
  unsigned int offset = 0;
  for (i = 0; i < 4; i++) {
    if (part_table && part_table_last_elem <= maxpart) {
      struct vupartition_t *new = &part_table[i+1];
      new->bootflag = vumbr_header.vumbrpart[i].bootflag;
      new->type = vumbr_header.vumbrpart[i].type;
      new->readonly = 0;
      new->LBAbegin = le32toh(vumbr_header.vumbrpart[i].lba_begin);
      new->LBAnoblocks = le32toh(vumbr_header.vumbrpart[i].lba_noblocks);
    }
    if(vumbr_header.vumbrpart[i].type == 5) {/* extended partition*/
      if (ext_part_base == 0)
        ext_part_base = le32toh(vumbr_header.vumbrpart[i].lba_begin);
      else
        printk(KERN_ERR "There are more than one extended partitions against the specifications\n", vumbr_header.vumbrpart[i].type);
    }
  }
  /* Read the chain of logical partitions inside the extended partition */
  while (ext_part_base > 0) {
    off_t base = ((off_t)(ext_part_base + offset)) << IDE_BLOCKSIZE_LOG;
    pread64(fd, &vumbr_header, sizeof(vumbr_header), base);
    if(memcmp(vumbr_header.signature, vumbr_signature, 2) != 0) {
      printk(KERN_ERR "Bad signature in block %lld=%x %x\n", base, vumbr_header.signature[0],vumbr_header.signature[1]);
      ext_part_base = 0;
    } else {
      if(vumbr_header.vumbrpart[0].type != 0) {
        ++part_table_last_elem;
        if (part_table && part_table_last_elem <= maxpart) {
          struct vupartition_t *new = &part_table[part_table_last_elem];
          new->bootflag = vumbr_header.vumbrpart[0].bootflag;
          new->type = vumbr_header.vumbrpart[0].type;
          new->readonly = 0;
          new->LBAbegin = le32toh(vumbr_header.vumbrpart[0].lba_begin) + ext_part_base + offset;
          new->LBAnoblocks = le32toh(vumbr_header.vumbrpart[0].lba_noblocks);
        }
        if(vumbr_header.vumbrpart[1].type == 5)
          offset = le32toh(vumbr_header.vumbrpart[1].lba_begin);
        else
          ext_part_base=0;
      }
    }
  }
  return part_table_last_elem;
}

/* return number subdev */
static inline ssize_t _ck_size(struct vupartition_t *partition, off_t offset) {
	if(partition) {
		if(((uint64_t)offset >> IDE_BLOCKSIZE_LOG) < partition->LBAnoblocks)
			offset += PART_ADDRBASE(partition);
		else return -1;
	}
  return offset;
}

static inline size_t _vumbr_pread64(int fd, void *buf, size_t count, off_t offset, struct vumbrfd_t *vumbrfd) {
	if((offset = _ck_size(vumbrfd->partition, vumbrfd->offset)) < 0)
		return 0;
	return pread64(fd, buf, count, offset);
}

static inline size_t _vumbr_pwrite64(int fd, const void *buf, size_t count, off_t offset, struct vumbrfd_t *vumbrfd) {
	if((offset = _ck_size(vumbrfd->partition, vumbrfd->offset)) < 0)
		return 0;
	return pwrite64(fd, buf, count, offset);
}

/******************************************************************************/
/***********************************SYSCALL************************************/

int vumbr_confirm_subdev(int subdev, struct vudev_t *vudev) {
  struct vumbr_t *vumbr = vudev_get_private_data(vudev);
	return subdev >= 0 && subdev <= vumbr->part_table_last_elem && vumbr->part_table[subdev].type != 0;
}

int vumbr_open(const char *pathname, mode_t mode, struct vudevfd_t *vdefd) {
  struct vumbr_t *vumbr = vudev_get_private_data(vdefd->vudev);
  struct vumbrfd_t *vumbrfd;
  int subdev;
	if((vumbrfd = calloc(1, sizeof(struct vumbrfd_t))) == NULL) {
		errno = ENOMEM;
		return -1;
	}
  subdev = vdefd->subdev;
	if (vumbr_confirm_subdev(subdev, vdefd->vudev))
		vumbrfd->partition = &vumbr->part_table[subdev];
	else {
    free(vumbrfd); 
		errno = EINVAL;
		return -1;
  } 
	vdefd->fdprivate = vumbrfd;
  return 0;
}

int vumbr_close(struct vudevfd_t *vdefd) {
  struct vumbrfd_t *mbrfd = vdefd->fdprivate;
  free(mbrfd);
  return 0;
}

ssize_t vumbr_read(struct vudevfd_t *vdefd, void *buf, size_t count) {
	struct vumbrfd_t *vumbrfd = vdefd->fdprivate;
  struct vumbr_t *vumbr = vudev_get_private_data(vdefd->vudev);
  ssize_t ret_value = _vumbr_pread64(vumbr->fd, buf, count, vumbrfd->offset, vumbrfd);
  if(ret_value != -1)
    vumbrfd->offset += ret_value;
  return ret_value;
}

ssize_t vumbr_write(struct vudevfd_t *vdefd, const void *buf, size_t count) {
	struct vumbrfd_t *vumbrfd = vdefd->fdprivate;
  struct vumbr_t *vumbr = vudev_get_private_data(vdefd->vudev);
  if(vumbrfd->partition->readonly) {
    errno = EBADF; 
		return -1;
  }
  ssize_t ret_value = _vumbr_pwrite64(vumbr->fd, buf, count, vumbrfd->offset, vumbrfd);
  if(ret_value != -1)
    vumbrfd->offset += ret_value;
  return ret_value;
}

ssize_t vumbr_pread64(struct vudevfd_t *vdefd, void *buf, size_t count, off_t offset) {
  struct vumbr_t *vumbr = vudev_get_private_data(vdefd->vudev);
	return _vumbr_pread64(vumbr->fd, buf, count, offset, vdefd->fdprivate);
}

ssize_t vumbr_pwrite64(struct vudevfd_t *vdefd, const void *buf, size_t count, off_t offset) {
  struct vumbr_t *vumbr = vudev_get_private_data(vdefd->vudev);
  struct vumbrfd_t *vumbrfd = vdefd->fdprivate;
  if(vumbrfd->partition->readonly) {
    errno = EBADF; return -1;
  }
	return _vumbr_pwrite64(vumbr->fd, buf, count, offset, vumbrfd);
}

off_t vumbr_lseek(struct vudevfd_t *vdefd, off_t offset, int whence) {
  struct vumbrfd_t *vumbrfd = vdefd->fdprivate;
  off_t ret_value;
	switch (whence) {
		case SEEK_SET:
      ret_value = vumbrfd->offset = offset;
      break;
		case SEEK_CUR:
      ret_value = vumbrfd->offset = vumbrfd->offset + offset;
      break;
		case SEEK_END: {
		  if(vumbrfd->partition == NULL) {
				struct vumbr_t *vumbr = vudev_get_private_data(vdefd->vudev);
			  ret_value = vumbrfd->offset = vumbr->size + offset;
		  } else
			  ret_value = vumbrfd->offset = PART_ADDRMAX(vumbrfd->partition) + offset;
		  break;
    }
    default: errno = EINVAL; ret_value = (off_t) -1; break;
	}
  return ret_value;
}

int vumbr_ioctl(struct vudevfd_t *vdefd, unsigned long request, void *addr){
	if (vdefd) {
		struct vumbr_t *vumbr = vudev_get_private_data(vdefd->vudev);
		struct vumbrfd_t *vumbrfd = vdefd->fdprivate;
		switch (request) {
			case BLKROGET: {
											 *(int *)addr = vumbrfd->partition->readonly;
											 break;
										 }
			case BLKROSET:{
											vumbrfd->partition->readonly = (*(int *)addr > 0)? 1:0;
											break;
										}
			case BLKSSZGET:
										*(int *)addr = IDE_BLOCKSIZE;
										break;
			case BLKGETSIZE: 
										*(uint32_t *)addr = vumbrfd->partition->LBAnoblocks;
										break;
			case BLKGETSIZE64: 
										*(uint64_t *)addr = (vumbrfd->partition->LBAnoblocks) << IDE_BLOCKSIZE_LOG;
										break;
			case BLKRRPART: {
												int newpart_table_last_elem = _read_mbr(vumbr->fd, vumbr->size, NULL, 0);
												struct vupartition_t *newpart = calloc(newpart_table_last_elem + 1, sizeof(struct vupartition_t));
												if (newpart == NULL)
													errno = ENOMEM;
												else {
													free(vumbr->part_table);
													vumbr->part_table = newpart;
													vumbr->part_table_last_elem = _read_mbr(vumbr->fd, vumbr->size, newpart, newpart_table_last_elem);
												}
												break;
											}
			case HDIO_GETGEO: {
													if (ioctl(vumbr->fd, HDIO_GETGEO, addr) < 0) {
														struct hd_geometry *geometry = addr;
														geometry->heads = 255;
														geometry->sectors = 63;
														geometry->cylinders = (vumbr->size >> IDE_BLOCKSIZE_LOG) / (geometry->heads * geometry->sectors);
														if (geometry->cylinders * geometry->heads * geometry->sectors < (vumbr->size >> IDE_BLOCKSIZE_LOG))
														geometry->cylinders += 1;
													}
													break;
												}
			default: errno = EINVAL; return -1;
		}
		return 0;
	} else
		return -1;
}

void *vumbr_init(const char *source, unsigned long flags, const char *args, struct vudev_t *vudev) {
  struct vumbr_t *vumbr;
	if((vumbr = calloc(1, sizeof(struct vumbr_t))) == NULL) {
		errno = ENOMEM;
		return NULL;
	}
	if((vumbr->fd = open(source, O_RDWR|O_CLOEXEC)) == -1) {
		free(vumbr);
		return NULL;
	}
	if((vumbr->size = lseek(vumbr->fd, 0, SEEK_END)) == -1)  {
    if(ioctl(vumbr->fd, BLKGETSIZE64, &(vumbr->size)) < 0) {
      close(vumbr->fd);
  		free(vumbr);
  	  return NULL;
    }
	}
	vumbr->part_table_last_elem = _read_mbr(vumbr->fd, vumbr->size, NULL, 0);
	vumbr->part_table = calloc(vumbr->part_table_last_elem + 1, sizeof(struct vupartition_t));
	if (vumbr->part_table == NULL) {
		close(vumbr->fd);
		free(vumbr);
		errno = ENOMEM;
		return NULL;
	}
	vumbr->part_table_last_elem = _read_mbr(vumbr->fd, vumbr->size, vumbr->part_table, vumbr->part_table_last_elem);

	vudev_set_devtype(vudev, S_IFBLK);
	return vumbr;
}

int vumbr_fini(void *private_data) {
	struct vumbr_t *vumbr = private_data;
  if(vumbr) {
		if (vumbr->part_table)
			free(vumbr->part_table);
    close(vumbr->fd);
    free(vumbr);
    private_data = NULL;
  }
	return 0;
}

struct vudev_operations_t vudev_ops = {
	.confirm_subdev = vumbr_confirm_subdev,
  .open = vumbr_open,
  .close = vumbr_close,
  .read = vumbr_read,
  .write = vumbr_write,
	.pread = vumbr_pread64,
	.pwrite = vumbr_pwrite64,
  .lseek = vumbr_lseek,
  .ioctl = vumbr_ioctl,
  .init = vumbr_init,
  .fini = vumbr_fini,
};

/*
 *  entren --- a traffic analyser, may also be used as an intrusion detection system
 *  Copyright (C) 2002  Chris Aumann <c_aumann@users.sourceforge.net>
 *
 * This file is part of entren.
 * 
 * entren is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * entren is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with entren; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#ifndef linux
#include "entren.h"

/* open_bpf(): 
 *
 * oeffnet /dev/bpf[0-999] fuer nic_device das in cap_dev angegeben sein muss
 * setzt die notwendigen io_ctl()s und gibt den descriptor zurueck
 *
 */


int
open_bpf(struct cap_dev *dev) {

        int     fd;
        int     i = 0;
        
        struct  ifreq    ifrq;
        char    bpf_device[sizeof("/dev/bpf000")];    
               
        

    /* set the device */
    strlcpy(ifrq.ifr_name, dev->nic_device, sizeof(ifrq.ifr_name));
  
  
    /* Go through all the minors and find one that isn't in use. */
    /* thx to libpcap */
    do {
        sprintf(bpf_device, "/dev/bpf%d", i++);
        fd = open(bpf_device, O_RDONLY);
    } while (fd < 0 && errno == EBUSY);

    if (fd < 0) {
        perror("can't open /dev/bpf[0-999], are you r00t?");
        return -1;
    }
  

    /* get required buffer length */
    if (ioctl(fd, BIOCGBLEN, &dev->bio_len) == -1) {
        perror("ioctl (BIOCGLEN) failed.");
        return -1;
    }
  

    /* set buffer length */
    if (ioctl(fd, BIOCSBLEN, &dev->bio_len) == -1) {
        perror("ioctl (BIOCSBLEN) failed.");
        return -1;
    }
  
    /* set interface */
    if (ioctl(fd, BIOCSETIF, &ifrq) == -1) {
        perror("ioctl (BIOCSETIF) failed.");
        return -1;
    }
    if (foreground)
        printf("using device: %s\n", dev->nic_device);
  
    /* enable promisc mode */
    if (foreground)
        printf("promisc mode: %s\n", (dev->promisc) ? "yes" : "no");
    if (dev->promisc)
        if (ioctl(fd, BIOCPROMISC, &dev->promisc) == -1) {
            perror("ioctl (BIOCPROMISC) failed\n");
            return -1;
        }
  
    /* get link layer type of device */
    if (ioctl(fd, BIOCGDLT, &dev->ll_type) == -1) {
        perror("ioctl (BIOCGDLT) failed");
        return -1;
    }

    /* enable 'immediate mode' */
    i = 1;
    if (ioctl(fd, BIOCIMMEDIATE, &i) == -1) {
        perror("ioctl (BIOCIMMEDIATE) failed\n");
        return -1;
    }


    /* 0 == capture only incoming packages */
    /* 1 == capture outgoing packages too */
    if (foreground)
        printf("capture outgoing packages: %s\n", (dev->out) ? "yes" : "no");
        
    if (ioctl(fd, BIOCSSEESENT, &dev->out) == -1) {
        perror("ioctl (BIOSGSEESENT) falied");
        return -1;
    }

    dev->fd = fd;
    return fd;

}
#endif
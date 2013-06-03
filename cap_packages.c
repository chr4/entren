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


#include "entren.h"

/* cap_packages()
 * Capture the packages, cast them into the headers, 
 * and give them to the check-functions
 */
int
cap_packages(void) {

        int     n;    
        char    buffy[LEN];



/********** <LINUX> **********/
#ifdef linux        
        int          sock_fd;
        socklen_t    socklen;

        struct ifreq       ifr;
        struct sockaddr_in *myaddr;

        struct ethhdr      *ethh;

/********** </LINUX> **********/



/********** <BSD> **********/
#else
        /* BPF Header */
        struct bpf_hdr     *bpfh;
#endif
/********** </BSD> **********/



        /* The headers */
        struct ip          *iph;
        struct tcphdr      *tcph;
        struct icmp        *icmph;
        struct udphdr      *udph;
        
        /* Pointer to the payload */
        char    *data;

        int     offset;
        
        
        

/********** <LINUX> **********/
#ifdef linux
    if ((sock_fd = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL))) == -1) {
        perror("socket() failed (are you root?)");
        exit(1);
    }

    bind(sock_fd, &bind_addr, sizeof(struct sockaddr));
    
    if (strstr(bind_addr.sa_data, "ppp"))
        offset = 0;
    else
        offset = sizeof(struct ethhdr);



    /* Turn on the promiscous-mode */
    if (promisc) {
        
        memset(&ifr, 0, sizeof(ifr));
        
        /* Set the device name */
        strlcpy(ifr.ifr_name, bind_addr.sa_data, sizeof(ifr.ifr_name));

        /* Get current flags */
        if (ioctl(sock_fd, SIOCGIFFLAGS, &ifr) == -1) {
            perror("ioctl(SIOCGIFFLAGS) failed");
            exit(1);
        }
	        
        if ((ifr.ifr_flags & IFF_PROMISC) == 0) {

            /* Promisc mode */
            ifr.ifr_flags |= IFF_PROMISC;
            if (ioctl(sock_fd, SIOCSIFFLAGS, &ifr) == -1) {
                perror("ioctl() failed. Cannot enable promisc mode");
                exit(1);
            }
        }
    }
    
    /* deactivate promisc mode */
    else {
    
        memset(&ifr, 0, sizeof(ifr));
        strlcpy(ifr.ifr_name, bind_addr.sa_data, sizeof(ifr.ifr_name));
        if (ioctl(sock_fd, SIOCGIFFLAGS, &ifr) == -1) {
            perror("ioctl(SIOCGIFFLAGS) failed");
            exit(1);
        } 
        if (ifr.ifr_flags & IFF_PROMISC) {
        
            ifr.ifr_flags &= ~IFF_PROMISC;
            if (ioctl(sock_fd, SIOCSIFFLAGS, &ifr) == -1) {
                perror("Cannot disable promisc mode");
                exit(1);
            }
        }    
    }



    if (!outgoing) {
        
        memset(&ifr, 0, sizeof(ifr));
        strlcpy(ifr.ifr_name, bind_addr.sa_data, sizeof(ifr.ifr_name));

        if (ioctl(sock_fd, SIOCGIFADDR, &ifr) == -1) {
            perror("ioctl() failed");
            exit(1);           
        }
            
        myaddr = (struct sockaddr_in *) &ifr.ifr_addr;
        
        if (foreground)
            printf("%s has address: %s\n", 
                    ifr.ifr_name, inet_ntoa(myaddr->sin_addr));
    }


    for (;;) {
        
        socklen = sizeof(struct sockaddr);
        if ((n = recvfrom(sock_fd, buffy, LEN, 0, &bind_addr, &socklen)) == -1) {
            perror("read() error");
            break;
        }
    
        if (offset) {
            /* Cast the ethernet header */
            ethh = (struct ethhdr *) buffy;
        
            /* Protocol isn't IP? Read next packet. */
            if (htons(ethh->h_proto) != ETH_P_IP) {
                if (foreground)
                    puts("non-ip packet captured");
                    
                continue;
            }
        }

/********** </LINUX> **********/







/********** <BSD> **********/
#else        


    /* Open the BPF device */
    if ((open_bpf(&dev)) == -1)
        exit(1);

    /* Continuous loop */
    for(;;) {
  
        if ((n = read(dev.fd, buffy, sizeof(buffy))) <= 0 ) {
            perror("read() error\n");
            break;
        }
        
        /* bpf header */
        bpfh = (struct bpf_hdr *) buffy;
        
        /* ethernet header vorhanden? */
        /* dev.ll_type wird von open_bpf gesetzt */
        if (dev.ll_type == DLT_EN10MB) 
            offset = bpfh->bh_hdrlen + sizeof(struct ether_header);
            
        else if (dev.ll_type == DLT_NULL)
            offset = bpfh->bh_hdrlen + 4; /* sry, dunno what those 4 bytes are for */
            
        else {
            if (foreground)
                fprintf(stderr, "unsupportet link layer type\n"); 
            continue;
        }

/********** </BSD> **********/
#endif
 
 
 
            
        /* ip header */
        iph = (struct ip *) (buffy + offset);
        buffy[n] = '\0';    /* NULL-terminate the payload */
        





/********** <LINUX> **********/
#ifdef linux
        if (!outgoing)
        
            /* If outgoing mode is not set, we don't want */
            /* the packages from this host */
            if (iph->ip_src.s_addr == myaddr->sin_addr.s_addr)
                continue;
#endif 
/********** </LINUX> **********/




       
        /* protokoll check */
        switch (iph->ip_p) {
        
            /* wenn TCP */
            case IPPROTO_TCP: 
                              /* TCP header */
                              tcph = (struct tcphdr *) (buffy + offset + (iph->ip_hl * 4));
                              
                              /* Payload */
                              data = buffy + offset + (iph->ip_hl * 4) + (tcph->th_off * 4);
                                
                              /* call the check-function */
                              tcp_log(iph, tcph, data);
                              break;
                        
            /* wenn ICMP */                        
            case IPPROTO_ICMP:  
                               icmph = (struct icmp *) (buffy + offset + (iph->ip_hl * 4));
                               data = buffy + offset + (iph->ip_hl * 4) + sizeof(struct icmp);
                        
                               icmp_log(iph, icmph, data);
                               break;
                        
            /* wenn UDP */                        
            case IPPROTO_UDP: 
                               udph = (struct udphdr *) (buffy + offset + (iph->ip_hl * 4));
                               data = buffy + offset + (iph->ip_hl * 4) + sizeof(struct udphdr);
                        
                               udp_log(iph, udph, data);
                               break;
                        
            default:          /* If we are in the foreground mode, display an error */
                               if (foreground)
                                   fprintf(stderr, "unknown protocol: %d \n\n", iph->ip_p);
                               break;
        }

  
    }
  
    return 0;
}

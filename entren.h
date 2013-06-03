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


#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <syslog.h>
#include <sys/wait.h>


#include <netinet/in.h>

/* wenn kein linux */
#ifndef linux 
#include "open_bpf.h"
#include <netinet/in_systm.h>

/* wenn linux */
#else
#include <sys/ioctl.h>
#include <linux/if.h>

#define __FAVOR_BSD
#endif

#include <netinet/ip.h>

#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netdb.h>

#include <signal.h>
#include <regex.h>


#define LEN     4096    /* buffer lenght */
#define MAXARG  64      /* max argument number (for prase_args() ) */
#define UNSET   -1

#define ICMPTYPELEN 30 /* max. icmp type nr. */


/* The config-file tags */

/* Rule-keywords (At the beginning of each rule) */
#define CONF_TCP_TAG    "[tcp]"
#define CONF_UDP_TAG    "[udp]"
#define CONF_ICMP_TAG   "[icmp]"

/* keywords */
#define CONF_FROM       "from"
#define CONF_TO         "to"
#define CONF_SPORT      "source_port"
#define CONF_DPORT      "dest_port"
#define CONF_TCP_FLAGS  "tcp_flags"
#define CONF_ICMP_TYPE  "icmp_type"
#define CONF_GREP       "grep"
#define CONF_EGREP      "egrep"
#define CONF_COMMAND1   "command1"
#define CONF_COMMAND2   "command2"
#define CONF_COUNT      "count"
#define CONF_DELAY      "delay"
#define CONF_SCANMODE   "portscan_mode"
#define CONF_TIME       "time"
#define CONF_LOGSTR     "logstr"

#define CONF_CAP_OUT    "capture_outgoing"
#define CONF_DEVICE     "device"
#define CONF_PROMISC    "promisc"
#define CONF_USE_SYSTEM "use_system"
#define CONF_LOG_LEVEL  "log_level"


/* The different log-levels */
#define CONF_LL_EMERG   "emerg"   /* system is unusable */
#define CONF_LL_ALERT   "alert"   /* action must be taken immediately */
#define CONF_LL_CRIT    "crit"    /* critical conditions */
#define CONF_LL_ERR     "err"     /* error conditions */
#define CONF_LL_WARNING "warning" /* warning conditions */
#define CONF_LL_NOTICE  "notice"  /* normal but significant condition */
#define CONF_LL_INFO    "info"    /* informational */
#define CONF_LL_DEBUG   "debug"   /* debug-level messages */



/* Keywords that will be replaced by the current values */
/* logstr / command1 / command2 */
#define GET_SIP         "%sip"
#define GET_DIP         "%dip"
#define GET_SPORT       "%sport"
#define GET_DPORT       "%dport"
#define GET_TCP_FLAGS   "%tcp_flags"
#define GET_ICMP_TYPE   "%icmp_type"
#define GET_GREPSTRING  "%grep"
#define GET_TIME        "%time"
#define GET_DATA        "%data"

/* default config file */
#define DEFAULT_CONFIG_FILE "/etc/entren.conf"

/* a short macro to overide spaces in a string */
#define no_space(x) while(isspace(*x)) x++


/* if Linux... */
#ifdef linux
    struct  sockaddr bind_addr;
    
    char    promisc;
    char    outgoing;


/* If BSD */
#else
    /* struct for open_bpf() */
    struct cap_dev dev;
#endif


char  foreground;    /* foreground flag  */
char  use_system;    /* use system() ?   */
char  log_level;     /* Log-Level to use */





/* Linked list for the TCP-Rules */
struct tcp_rule {

    in_addr_t sip;    /* source ip, network byte order */
    in_addr_t dip;    /* dest ip */
    
    char not_sip;     /* invert-flags: wenn gesetzt, werden alle */
    char not_dip;     /* ips _ausser_ sip/dip beachtet */
    
    
    in_port_t sport;    /* source port, network byte order */  
    in_port_t dport;    /* dest port, network byte order */
    
    char not_sport;   /* negativ flags fuer die ports: wenn gesetzt, */
    char not_dport;   /* werden alle ports _ausser_ sport/dport true */
    
    
    char    syn;        /* tcp flags */
    char    ack;        /* 0 = nicht gesetzt */
    char    rst;        /* 1 = gesetzt */
    char    fin;        /* -1 = ignorieren */
    char    psh;
    char    urg;
    
    
    char    scan;       /* portscan mode: packet nur true wenn dport anders */
                        /* als im letzten packet */
                        
    u_short lastport;   /* speicher fuer den dport des letzten packetes */
                        /* (wird fuer den portscan modus gebraucht */
    
    char    *grep;      /* grepstring: packet nur true wenn der string "grep" */
                        /* im packet enthalten ist (strstr() == true) */
                        
    char    egrep;      /* "grep" ist ein regulaerer ausdruck. packet true */
                        /* wenn der regulaere ausdruck zutrifft (langsam) */
                        
    char    not_grep;   /* negativ flag: packet nur true wenn der string oder */
                        /* regulaere ausdruck _nicht_ im packet vorkommt */
    
    int     count;      /* die anzahl der packete die true sein muessen, bis */
                        /* das programm reagiert */
                        
    int     true;       /* die zahl der bissher gefundenen true-packete */ 
    
    int     time;       /* zeit in sekunden, in der die packete eintreffen 
                         * muessen, damit das programm reagiert
                         * (wenn "count" packete in "time" sekunden true,
                         * dann...) 
                         */
                         
    char    first;      /* erstes packet dieser regel was "true" ist? */
                        /* wenn ja, speichere aktuelle zeit in "start_time */
                        
    u_long  start_time; /* hier wird die zeit des ersten eintreffenden "true" */
                        /* packetes festgehalten (zum abgleich mit "time" */
    
    char    *command1;  /* systemcomanndo, wird ausgefuehrt sobald "count" */
                        /* packete innerhalb von "time" true sind */
                        
    char    *command2;  /* zweites systemcomando, wird ausgefuehrt nachdem */
                        /* nach dem ausfuehren von command1 "sec" sekunden */
                        /* vergangen sind */
                        
    int     sec;        /* die sekunden die zu zwischen command1 und command2 */
                        /* zu warten sind (argument an sleep() ) */
    
    char    *logstr;    /* der string fuer syslog. */
    
    
    struct tcp_rule *next; /* naechstes element in der verketteten liste */
};



/* udp_rule: die regeln fuer udp-packete */
/* werden vom programm nacheinander durchlaufen */
struct udp_rule {

    in_addr_t sip;    /* source ip, network byte order */
    in_addr_t dip;    /* dest ip */
    
    char not_sip;     /* negativ-flags: wenn gesetzt, werden alle */
    char not_dip;     /* ips _ausser_ sip/dip beachtet */
    
    
    in_port_t sport;    /* source port, network byte order */  
    in_port_t dport;    /* dest port, network byte order */
    
    char not_sport;   /* negativ flags fuer die ports: wenn gesetzt, */
    char not_dport;   /* werden alle ports _ausser_ sport/dport true */
    

    char    *grep;      /* grepstring: packet nur true wenn der string "grep" */
                        /* im packet enthalten ist (strstr() == true) */
                        
    char    egrep;      /* "grep" ist ein regulaerer ausdruck. packet true */
                        /* wenn der regulaere ausdruck zutrifft (langsam) */
                        
    char    not_grep;   /* negativ flag: packet nur true wenn der string oder */
                        /* regulaere ausdruck _nicht_ im packet vorkommt */
    
    int     count;      /* die anzahl der packete die true sein muessen, bis */
                        /* das programm reagiert */
                        
    int     true;       /* die zahl der bissher gefundenen true-packete */ 
    
    int     time;       /* zeit in sekunden, in der die packete eintreffen 
                         * muessen, damit das programm reagiert
                         * (wenn "count" packete in "time" sekunden true,
                         * dann...) 
                         */
                         
    char    first;      /* erstes packet dieser regel was "true" ist? */
                        /* wenn ja, speichere aktuelle zeit in "start_time */
                        
    u_long  start_time; /* hier wird die zeit des ersten eintreffenden "true" */
                        /* packetes festgehalten (zum abgleich mit "time" */
    
    char    *command1;  /* systemcomanndo, wird ausgefuehrt sobald "count" */
                        /* packete innerhalb von "time" true sind */
                        
    char    *command2;  /* zweites systemcomando, wird ausgefuehrt nachdem */
                        /* nach dem ausfuehren von command1 "sec" sekunden */
                        /* vergangen sind */
                        
    int     sec;        /* die sekunden die zu zwischen command1 und command2 */
                        /* zu warten sind (argument an sleep() ) */
    
    char    *logstr;    /* der string fuer syslog. */
    
    
    struct udp_rule *next; /* naechstes element in der verketteten liste */
};




/* icmp_rule: die regeln fuer icmp-packete */
/* werden vom programm nacheinander durchlaufen */
struct icmp_rule {

    in_addr_t sip;    /* source ip, network byte order */
    in_addr_t dip;    /* dest ip */
    
    char not_sip;     /* negativ-flags: wenn gesetzt, werden alle */
    char not_dip;     /* ips _ausser_ sip/dip beachtet */
    
    
    char    type[ICMPTYPELEN];  /* array fuer icmp-types */
                                  /* default == 1 */
                                  /* wenn der eintrag im array fuer den */
                                  /* icmp-type des packetes 0 ist, ist das */
                                  /* packet false */
                                  /* (noch nicht wirklich ausgereift, */
                                  /* ich weiss) */


    char    *grep;      /* grepstring: packet nur true wenn der string "grep" */
                        /* im packet enthalten ist (strstr() == true) */
                        
    char    egrep;      /* "grep" ist ein regulaerer ausdruck. packet true */
                        /* wenn der regulaere ausdruck zutrifft (langsam) */
                        
    char    not_grep;   /* negativ flag: packet nur true wenn der string oder */
                        /* regulaere ausdruck _nicht_ im packet vorkommt */
    
    int     count;      /* die anzahl der packete die true sein muessen, bis */
                        /* das programm reagiert */
                        
    int     true;       /* die zahl der bissher gefundenen true-packete */ 
    
    int     time;       /* zeit in sekunden, in der die packete eintreffen 
                         * muessen, damit das programm reagiert
                         * (wenn "count" packete in "time" sekunden true,
                         * dann...) 
                         */
                         
    char    first;      /* erstes packet dieser regel was "true" ist? */
                        /* wenn ja, speichere aktuelle zeit in "start_time */
                        
    u_long  start_time; /* hier wird die zeit des ersten eintreffenden "true" */
                        /* packetes festgehalten (zum abgleich mit "time" */
    
    char    *command1;  /* systemcomanndo, wird ausgefuehrt sobald "count" */
                        /* packete innerhalb von "time" true sind */
                        
    char    *command2;  /* zweites systemcomando, wird ausgefuehrt nachdem */
                        /* nach dem ausfuehren von command1 "sec" sekunden */
                        /* vergangen sind */
                        
    int     sec;        /* die sekunden die zu zwischen command1 und command2 */
                        /* zu warten sind (argument an sleep() ) */
    
    char    *logstr;    /* der string fuer syslog. */
    
    
    struct icmp_rule *next; /* naechstes element in der verketteten liste */
};




struct tcp_rule *tcp_rules;     /* linked list with tcp rules */
struct udp_rule *udp_rules;     /* linked list with udp rules */
struct icmp_rule *icmp_rules;   /* linked list with icmp rules */


/************************/
/****** PROTOTYPES ******/
/************************/

#ifndef strlcpy
    size_t strlcpy(char *dst, const char *src, size_t siz);
#endif

#ifndef strlcat
    size_t strlcat(char *dst, const char *src, size_t siz);
#endif

int strsub(char *, char *, char *, int);
int regex_match(const char *, char *);


int cap_packages(void);
#ifndef linux
    int open_bpf(struct cap_dev *);
#endif

void add_tcp_rule (in_addr_t, in_addr_t, char, char,
        in_port_t, in_port_t, char, char,
        char, char, char,
        char, char, char,
        char,
        char *, char, char,
        int,
        int,  char *, char *, int,
        char *);

void add_udp_rule(in_addr_t, in_addr_t, char, char,
        in_port_t, in_port_t, char, char,
        char *, char, char,
        int,
        int, char *, char *, int,
        char *);
        
void add_icmp_rule(in_addr_t, in_addr_t, char, char,
        char type[ICMPTYPELEN],
        char *, char, char,
        int,
        int, char *, char *, int,
        char *);

void print_rules(void);


int tcp_log (struct ip *, struct tcphdr *, char *);
int udp_log (struct ip *, struct udphdr *, char *);
int icmp_log (struct ip *, struct icmp *, char *);

int readconf(char *);
int key_value(char *, char *, int, char *, int);
int parse_args(char *, char **, int);
int not_set(char *, char *, int);
void cut_crlf(char *);

int exec_cmd(char *);
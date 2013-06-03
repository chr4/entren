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


#define TCP  1
#define UDP  2
#define ICMP 3

/* zeilenzaehler */
int     linecount = 0;




/* tcp|udp|icmp-bla strukturen
 * speichern temporaer die werte aus dem config file, und fuegen am ende
 * des rulesets, die werte als regel ans ende der regel-listen an
 */
 
struct tcpbla {

    in_addr_t sip;    /* source ip, network byte order */
    in_addr_t dip;    /* dest ip */
    
    char not_sip;     /* negativ-flags: wenn gesetzt, werden alle */
    char not_dip;     /* ips _ausser_ sip/dip beachtet */
    
    
    u_short sport;    /* source port, network byte order */  
    u_short dport;    /* dest port, network byte order */
    
    char not_sport;   /* negativ flags fuer die ports: wenn gesetzt, */
    char not_dport;   /* werden alle ports _ausser_ sport/dport true */
    
    
    char    syn, ack, rst,    /* tcp flags */
            fin, psh, urg;    /* 0 = nicht gesetzt | 1 = gesetzt */
                              /* (default) -1 = ignorieren */
    
    
    char    scan;       /* portscan mode: packet nur true wenn dport anders */
                        /* als im letzten packet */
    
    char    grep[LEN];  /* grepstring: packet nur true wenn der string "grep" */
                        /* im packet enthalten ist (strstr() == true) */
                        
    char    egrep;      /* "grep" ist ein regulaerer ausdruck. packet true */
                        /* wenn der regulaere ausdruck zutrifft (langsam) */
                        
    char    not_grep;   /* negativ flag: packet nur true wenn der string oder */
                        /* regulaere ausdruck _nicht_ im packet vorkommt */
    
    int     count;      /* die anzahl der packete die true sein muessen, bis */
                        /* das programm reagiert */
                        
    int     time;       /* zeit in sekunden, in der die packete eintreffen 
                         * muessen, damit das programm reagiert
                         * (wenn "count" packete in "time" sekunden true,
                         * dann...) 
                         */
                         
    char    cmd1[LEN];  /* systemcomanndo, wird ausgefuehrt sobald "count" */
                        /* packete innerhalb von "time" true sind */
                        
    char    cmd2[LEN];  /* zweites systemcomando, wird ausgefuehrt nachdem */
                        /* nach dem ausfuehren von command1 "sec" sekunden */
                        /* vergangen sind */
                        
    int     sec;        /* die sekunden die zu zwischen command1 und command2 */
                        /* zu warten sind (argument an sleep() ) */
    
    char    logstr[LEN];/* der string fuer syslog. */
    

} tcp;


/* struktur zum fuellen der UDP optionen */
struct udpbla {

    in_addr_t sip;    /* source ip, network byte order */
    in_addr_t dip;    /* dest ip */
    
    char not_sip;     /* negativ-flags: wenn gesetzt, werden alle */
    char not_dip;     /* ips _ausser_ sip/dip beachtet */
    
    
    u_short sport;    /* source port, network byte order */  
    u_short dport;    /* dest port, network byte order */
    
    char not_sport;   /* negativ flags fuer die ports: wenn gesetzt, */
    char not_dport;   /* werden alle ports _ausser_ sport/dport true */
    
   
    char    grep[LEN];  /* grepstring: packet nur true wenn der string "grep" */
                        /* im packet enthalten ist (strstr() == true) */
                        
    char    egrep;      /* "grep" ist ein regulaerer ausdruck. packet true */
                        /* wenn der regulaere ausdruck zutrifft (langsam) */
                        
    char    not_grep;   /* negativ flag: packet nur true wenn der string oder */
                        /* regulaere ausdruck _nicht_ im packet vorkommt */
    
    int     count;      /* die anzahl der packete die true sein muessen, bis */
                        /* das programm reagiert */
                        
    int     time;       /* zeit in sekunden, in der die packete eintreffen 
                         * muessen, damit das programm reagiert
                         * (wenn "count" packete in "time" sekunden true,
                         * dann...) 
                         */
                         
    char    cmd1[LEN];  /* systemcomanndo, wird ausgefuehrt sobald "count" */
                        /* packete innerhalb von "time" true sind */
                        
    char    cmd2[LEN];  /* zweites systemcomando, wird ausgefuehrt nachdem */
                        /* nach dem ausfuehren von command1 "sec" sekunden */
                        /* vergangen sind */
                        
    int     sec;        /* die sekunden die zu zwischen command1 und command2 */
                        /* zu warten sind (argument an sleep() ) */
    
    char    logstr[LEN];/* der string fuer syslog. */

} udp;
        
        
/* Struktur zum fuellen der ICMP optionen */  
struct icmpbla {

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

   
    char    grep[LEN];  /* grepstring: packet nur true wenn der string "grep" */
                        /* im packet enthalten ist (strstr() == true) */
                        
    char    egrep;     /* "grep" ist ein regulaerer ausdruck. packet true */
                        /* wenn der regulaere ausdruck zutrifft (langsam) */
                        
    char    not_grep;   /* negativ flag: packet nur true wenn der string oder */
                        /* regulaere ausdruck _nicht_ im packet vorkommt */
    
    int     count;      /* die anzahl der packete die true sein muessen, bis */
                        /* das programm reagiert */
                        
    int     time;       /* zeit in sekunden, in der die packete eintreffen 
                         * muessen, damit das programm reagiert
                         * (wenn "count" packete in "time" sekunden true,
                         * dann...) 
                         */
                         
    char    cmd1[LEN];  /* systemcomanndo, wird ausgefuehrt sobald "count" */
                        /* packete innerhalb von "time" true sind */
                        
    char    cmd2[LEN];  /* zweites systemcomando, wird ausgefuehrt nachdem */
                        /* nach dem ausfuehren von command1 "sec" sekunden */
                        /* vergangen sind */
                        
    int     sec;        /* die sekunden die zu zwischen command1 und command2 */
                        /* zu warten sind (argument an sleep() ) */
    
    char    logstr[LEN];/* der string fuer syslog. */

} icmp;




/* zum zuruecksetzen der tcp struktur, und mit default werten fuellen */
void
clear_tcp(void) {

    /* alles auf 0 setzen */
    memset(&tcp, 0, sizeof(tcp));

    /* default werte einfuegen */
    tcp.count = 1; /* default: ein packet */
    
    tcp.syn = -1;  /* default: ignorieren = -1 */
    tcp.ack = -1;
    tcp.rst = -1;
    tcp.fin = -1;
    tcp.psh = -1;
    tcp.urg = -1;

    return;
}


/* zuruecksetzen der udp struktur, und mit default werten fuellen */
void
clear_udp(void) {

    /* alles auf 0 setzen */
    memset(&udp, 0, sizeof(udp));

    /* default werte einfuegen */
    udp.count = 1;  /* default: ein packet */

    return;
}


/* zuruecksetzen der icmp-struktur, und mit default werden fuellen */
void
clear_icmp(void) {

    /* alles auf 0 setzen */
    memset(&icmp, 0, sizeof(icmp));
    
    /* default werte einfuegen */
    memset(&icmp.type, 1, sizeof(icmp.type)); /* default: icmp-types auf 1 */

    icmp.count = 1; /* default: ein packet */

    return;
}



/* alle regel-strukturen zuruecksetzten */
/* und mit default-werten fuellen */
void
clear_structs(void) {

    clear_tcp();    /* clear tcp */
    clear_udp();    /* clear udp */
    clear_icmp();   /* clear icmp */

    return;
}


/* liest die naechste zeile von fz
 * und liefert den gelesenen string zurueck
 * bei fehler oder EOF wird NULL zurueckgegeben
 * anfuerende leerzeichen werden uebergangen
 * genau wie zeilen die mit einem '#' beginnen
 * fuer jede zeile wird der globale zaehler
 * linecount incrementiert.
 */
char *
get_line (FILE *fz) {

    	static char *p;
        char         buffy[LEN];

    again:

    if (fgets(buffy, LEN, fz) == NULL)
    	return NULL;    /* fehler / ende der zeile */

    linecount++;        /* globalen zeilenzaehler incrementieren */
    cut_crlf(buffy);    /* eventuelle \r\n's abschneiden */

    p = buffy;
    no_space(p); 	/* overide spaces */

    if(!strlen(p)) 	/* ignore empty lines */
    	goto again;


    if(*p == '#')	/* ignore comments */
    	goto again;

    return p;
}



/* sucht nach schluesselwoertern in key
 * wenn gefunden -> value der liste type 
 * zuordnen
 * bei falschen werten -> exit(1);
 */
int
add_to_list(char type, char *key, char *value) {

        char    tmp[99]; /* temporaerer puffer */
        char    *p;       
        char    flag;
        int     nr;
        struct  hostent *host;


    if (type == TCP) {

        if (!strcmp(key, CONF_FROM)) { /* source ip */
            /* negativ-flags suchen */
            tcp.not_sip = not_set(value, tmp, sizeof(tmp));
            
            /* nach host suchen. wenn nicht gefunden: exit */
            if ((host = gethostbyname(tmp)) == NULL) {
                fprintf(stderr, "host '%s' not found\n", value);
                exit(1);
            }
            tcp.sip = inet_addr(inet_ntop(host->h_addrtype, host->h_addr, 
                                tmp, sizeof(tmp)));
        }

        else if (!strcmp(key, CONF_TO)) {  /* dest ip */
            /* negativ-flags suchen */
            tcp.not_dip = not_set(value, tmp, sizeof(tmp));
            
            /* nach host suchen. wenn nicht gefunden: exit */
            if ((host = gethostbyname(tmp)) == NULL) {
                fprintf(stderr, "host '%s' not found\n", value);
                exit(1);
            }
            
            tcp.dip = inet_addr(inet_ntop(host->h_addrtype, host->h_addr, 
                                tmp, sizeof(tmp)));
        }
        
        else if (!strcmp(key, CONF_DPORT)) { /* dest port */
            tcp.not_dport = not_set(value, tmp, sizeof(tmp));
            tcp.dport = ntohs(atoi(tmp));
            /* wenn port ungueltig, fehlermeldung und exit */
            if (tcp.dport < 1 || tcp.dport > 65535) {
                fprintf(stderr, "bad tcp dest port, line %d\n", linecount);
                exit(1);
            }
        }

        else if (!strcmp(key, CONF_SPORT)) {
            tcp.not_sport = not_set(value, tmp, sizeof(tmp));
            tcp.sport = ntohs(atoi(tmp));
            if (tcp.sport < 1 || tcp.sport > 65535) {
                fprintf(stderr, "bad tcp source port, line %d\n", linecount);
                exit(1);
            }
        }

        else if (!strcmp(key, CONF_COUNT)) {
            tcp.count = atoi(value);
            if (tcp.count < 1) {
                fprintf(stderr, "bad tcp count value, line %d\n", linecount);
                exit(1);
            }
        }
        
        else if (!strcmp(key, CONF_DELAY)) {
            tcp.sec = atoi(value);
            if (tcp.sec < 0) {
                fprintf(stderr, "bad tcp delay value, line %d\n", linecount);
                exit(1);
            }
        }

        else if (!strcmp(key, CONF_SCANMODE)) {
            if (atoi(value) == 1)
                tcp.scan = 1;
        }

        else if (!strcmp(key, CONF_TIME)) {
            tcp.time = atoi(value);
            if (tcp.time < 1) {
                fprintf(stderr, "bad tcp time value, line %d\n", linecount);
                exit(1);
            }
        }

        else if (!strcmp(key, CONF_GREP))
            tcp.not_grep = not_set(value, tcp.grep, sizeof(tcp.grep));

        else if (!strcmp(key, CONF_EGREP)) {
            tcp.not_grep = not_set(value, tcp.grep, sizeof(tcp.grep));
            tcp.egrep = 1;
        }

        else if (!strcmp(key, CONF_TCP_FLAGS)) {
            /* die TCP flags */
    
            /* nach ' ' aufteilen */
            p = strtok(value, " ");
            while (p != NULL) {   /* solange bis keine elemente mehr gefunden */
                no_space(p); /* evt. leerzeichen entfernen */
                flag = not_set(p, tmp, sizeof(tmp));
                /* typ checken und wert zuweisen */
                if (!strcmp(tmp, "syn"))
                    tcp.syn = (flag) ? 0 : 1;
                else if (!strcmp(tmp, "ack"))
                    tcp.ack = (flag) ? 0 : 1;
                else if (!strcmp(tmp, "rst")) 
                    tcp.rst = (flag) ? 0 : 1;
                else if (!strcmp(tmp, "fin")) 
                    tcp.fin = (flag) ? 0 : 1;
                else if (!strcmp(tmp, "urg")) 
                    tcp.urg = (flag) ? 0 : 1;
                else if (!strcmp(tmp, "psh")) 
                    tcp.psh = (flag) ? 0 : 1;
                else {
                    fprintf(stderr, "wrong tcp flag: %s line: %d\n", tmp, linecount);
                    exit(1);
                }
                /* naechstes element suchen */
                p = strtok(NULL, " ");
            }
                
        }

        else if (!strcmp(key, CONF_COMMAND1))
            strlcpy(tcp.cmd1, value, sizeof(tcp.cmd1));

        else if (!strcmp(key, CONF_COMMAND2))
            strlcpy(tcp.cmd2, value, sizeof(tcp.cmd2));

        else if (!strcmp(key, CONF_LOGSTR))
            strlcpy(tcp.logstr, value, sizeof(tcp.logstr));
                
        else  {
            fprintf(stderr, "error in config file line %d  '%s = %s'\n", linecount, key, value);
            exit(1);
        }
  
  }

    if (type == UDP) {
  
       if (!strcmp(key, CONF_FROM)) {
            udp.not_sip = not_set(value, tmp, sizeof(tmp));
            if ((host = gethostbyname(tmp)) == NULL) {
                fprintf(stderr, "host '%s' not found\n", value);
                exit(1);
            }
            udp.sip = inet_addr(inet_ntop(host->h_addrtype, host->h_addr, 
                                tmp, sizeof(tmp)));
        }
        
        else if (!strcmp(key, CONF_TO)) {
            udp.not_dip = not_set(value, tmp, sizeof(tmp));
            if ((host = gethostbyname(tmp)) == NULL) {
                fprintf(stderr, "host '%s' not found\n", value);
                exit(1);
                }
            udp.dip = inet_addr(inet_ntop(host->h_addrtype, host->h_addr, 
                                tmp, sizeof(tmp)));
        }
        
        else if (!strcmp(key, CONF_DPORT)) {
            udp.not_dport = not_set(value, tmp, sizeof(tmp));
            udp.dport = ntohs(atoi(tmp));
            if (udp.dport < 1 || udp.dport > 65535) {
                fprintf(stderr, "bad udp dest port, line %d\n", linecount);
                exit(1);
            }
        }

        else if (!strcmp(key, CONF_SPORT)) {
            udp.not_sport = not_set(value, tmp, sizeof(tmp));
            udp.sport = ntohs(atoi(tmp));
            if (udp.sport < 1 || udp.sport > 65535) {
                fprintf(stderr, "bad udp source port, line %d\n", linecount);
                exit(1);
            }
        }

        else if (!strcmp(key, CONF_COUNT)) {
            udp.count = atoi(value);
            if (udp.count < 1) {
                fprintf(stderr, "bad udp count value, line %d\n", linecount);
                exit(1);
            }
        }
        
        else if (!strcmp(key, CONF_DELAY)) {
            udp.sec = atoi(value);
            if (udp.sec < 0) {
                fprintf(stderr, "bad udp delay value, line %d\n", linecount);
                exit(1);
            }
        }

        else if (!strcmp(key, CONF_TIME)) {
            udp.time = atoi(value);
            if (udp.time < 1) {
                fprintf(stderr, "bad udp time value, line %d\n", linecount);
                exit(1);
            }
        }

        else if (!strcmp(key, CONF_GREP))
            udp.not_grep = not_set(value, udp.grep, sizeof(udp.grep));

        else if (!strcmp(key, CONF_EGREP)) {
            udp.not_grep = not_set(value, udp.grep, sizeof(udp.grep));
            udp.egrep = 1;
        }

        else if (!strcmp(key, CONF_COMMAND1))
            strlcpy(udp.cmd1, value, sizeof(udp.cmd1));

        else if (!strcmp(key, CONF_COMMAND2))
            strlcpy(udp.cmd2, value, sizeof(udp.cmd2));

        else if (!strcmp(key, CONF_LOGSTR))
            strlcpy(udp.logstr, value, sizeof(udp.logstr));

        else  {
            fprintf(stderr, "error in config file line %d [udp] '%s = %s'\n", linecount, key, value);
            exit(1);
        }

  }
  
  
  if (type == ICMP) {

       if (!strcmp(key, CONF_FROM)) {
            icmp.not_sip = not_set(value, tmp, sizeof(tmp));
            if ((host = gethostbyname(tmp)) == NULL) {
                fprintf(stderr, "host '%s' not found\n", value);
                exit(1);
            }
            icmp.sip = inet_addr(inet_ntop(host->h_addrtype, host->h_addr, 
                                tmp, sizeof(tmp)));
        }
        
        else if (!strcmp(key, CONF_TO)) {
            icmp.not_dip = not_set(value, tmp, sizeof(tmp));
            if ((host = gethostbyname(tmp)) == NULL) {
                fprintf(stderr, "host '%s' not found\n", value);
                exit(1);
            }
            icmp.dip = inet_addr(inet_ntop(host->h_addrtype, host->h_addr, 
                                tmp, sizeof(tmp)));
        }

        else if (!strcmp(key, CONF_COUNT)) {
            icmp.count = atoi(value);
            if (icmp.count < 1) {
                fprintf(stderr, "bad icmp count value, line %d\n", linecount);
                exit(1);
            }
        }
        
        else if (!strcmp(key, CONF_DELAY)) {
            icmp.sec = atoi(value);
            if (icmp.sec < 0) {
                fprintf(stderr, "bad icmp delay value, line %d\n", linecount);
                exit(1);
            }
        }

        else if (!strcmp(key, CONF_TIME)) {
            icmp.time = atoi(value);
            if (icmp.time < 1) {
                fprintf(stderr, "bad icmp time value, line %d\n", linecount);
                exit(1);
            }
        }

        else if (!strcmp(key, CONF_GREP))
            icmp.not_grep = not_set(value, icmp.grep, sizeof(icmp.grep));

        else if (!strcmp(key, CONF_EGREP)) {
            icmp.not_grep = not_set(value, icmp.grep, sizeof(icmp.grep));
            icmp.egrep = 1;
        }

        else if (!strcmp(key, CONF_COMMAND1))
            strlcpy(icmp.cmd1, value, sizeof(icmp.cmd1));

        else if (!strcmp(key, CONF_COMMAND2))
            strlcpy(icmp.cmd2, value, sizeof(icmp.cmd2));

        else if (!strcmp(key, CONF_LOGSTR))
            strlcpy(icmp.logstr, value, sizeof(icmp.logstr));

        /* icmp type */
        else if (!strcmp(key, CONF_ICMP_TYPE)) {
            /* alles verbieten */
            /* (default: alles erlaubt) */
            for (nr = 0; nr <= ICMPTYPELEN; nr++)
                icmp.type[nr] = 0;

            /* durchgehen der einzelnden werte (durch ' ' getrennt) */
            p = strtok(value, " ");
            while (p != NULL) {
                no_space(p);    /* eventuelle leerzeichen entfernen */
                nr = atoi(p);   /* string in int umwandeln */

                if (nr > ICMPTYPELEN) {    /* wert gueltig? */
                    fprintf(stderr, "bad icmp type nr: %s line: %d\n", p, linecount);
                    exit(1);
                }
                 
                /* type "nr" durchlassen */       
                icmp.type[nr] = 1;
                        
                /* nachstes element in der liste */
                p = strtok(NULL, " ");
            }
        }
        
        else  {
            fprintf(stderr, "error in config file line %d [icmp] '%s = %s'\n", linecount, key, value);
            exit(1);
        }

  }


  return 0;
}


/* fuegt der rule-liste type eine neue regel 
 * mit den aktuellen werten in der struktur type
 * zu, und setzt die entsprechende struktur zurueck
 * wenn type != ICMP/UDP/TCP wird -1 zurueckgegeben
 */
int
append_list(char type) {

    switch (type) {
    
        case TCP:   /* mindestens eine reaktion muss gesetzt sein */
                    if (! (strlen(tcp.logstr)
                        || strlen(tcp.cmd1)
                        || strlen(tcp.cmd2))) {
                       
                        fprintf(stderr, "[tcp] at least one of this options must be set: 'logstr' 'command1' 'command2'\n");
                        exit(1);
                    }
                    
                    /* tcp regel anfuegen */
                    add_tcp_rule(tcp.sip, tcp.dip, 
                               tcp.not_sip, tcp.not_dip,
                               tcp.sport, tcp.dport, 
                               tcp.not_sport, tcp.not_dport,
                               tcp.syn, tcp.ack, tcp.rst, 
                               tcp.fin, tcp.psh, tcp.urg,
                               tcp.scan, 
                               tcp.grep, tcp.egrep, tcp.not_grep,
                               tcp.time,
                               tcp.count, tcp.cmd1, tcp.cmd2, tcp.sec,
                               tcp.logstr);
                    clear_tcp();    /* temporaere regelstruktur zuruecksetzen */
                    break;
                    
        case UDP:   /* mindestens eine reaktion muss gesetzt sein */
                    if (! (strlen(udp.logstr)
                        || strlen(udp.cmd1)
                        || strlen(udp.cmd2))) {
                       
                        fprintf(stderr, "[udp] at least one of this options must be set: 'logstr' 'command1' 'command2'\n");
                        exit(1);
                    }
                    
                    /* udp regel anfuegen */
                    add_udp_rule(udp.sip, udp.dip, 
                               udp.not_sip, udp.not_dip,
                               udp.sport, udp.dport, 
                               udp.not_sport, udp.not_dport,
                               udp.grep, udp.egrep, udp.not_grep,
                               udp.time,
                               udp.count, udp.cmd1, udp.cmd2, udp.sec,
                               udp.logstr);
                    clear_udp();    /* temporaere regelstruktur zuruecksetzen */
                    break;
                    
        case ICMP:  /* mindestens eine reaktion muss gesetzt sein */
                    if (! (strlen(icmp.logstr)
                        || strlen(icmp.cmd1)
                        || strlen(icmp.cmd2))) {
                       
                        fprintf(stderr, "[icmp] at least one of this options must be set: 'logstr' 'command1' 'command2'\n");
                        exit(1);
                    }
                    
                    /* icmp regel anfuegen */
                    add_icmp_rule(icmp.sip, icmp.dip, 
                                icmp.not_sip, icmp.not_dip,
                                icmp.type,
                                icmp.grep, icmp.egrep, icmp.not_grep,
                                icmp.time,
                                icmp.count, icmp.cmd1, icmp.cmd2, icmp.sec,
                                icmp.logstr);
                    clear_icmp();    /* temporaere regelstruktur zuruecksetzen */
                    break;
      
        default:    return -1;
                    break;
    }      

    return 0;
}


/*  global_pref()
 *  schaut nach globalen einstellungen.
 *  setzt sie. bei fehler exit(0);
 * 
 */
int
global_pref(char *key, char *value) {


    /* use system() ? */
    if (!strcmp(key, CONF_USE_SYSTEM)) {
        if (!atoi(value))
            use_system = 0;
    }

    /* witch loglevel? */
    else if (!strcmp(key, CONF_LOG_LEVEL)) {
        if (!strcmp(value, CONF_LL_EMERG))
            log_level = LOG_EMERG;
        else if (!strcmp(value, CONF_LL_ALERT))
            log_level = LOG_ALERT;        
        else if (!strcmp(value, CONF_LL_CRIT))
            log_level = LOG_CRIT;        
        else if (!strcmp(value, CONF_LL_ERR))
            log_level = LOG_ERR;                            
        else if (!strcmp(value, CONF_LL_WARNING))
            log_level = LOG_WARNING;        
        else if (!strcmp(value, CONF_LL_NOTICE))
            log_level = LOG_NOTICE;        
        else if (!strcmp(value, CONF_LL_INFO))
            log_level = LOG_INFO;        
        else if (!strcmp(value, CONF_LL_DEBUG))
            log_level = LOG_DEBUG;        
        else {
            fprintf(stderr, "Error in config-file line %d: unkown log-level: %s\n",
                    linecount, value);
            exit(1);
        }
    }


    /* das zu ueberwachende device */
    else if (!strcmp(key, CONF_DEVICE))
#ifdef linux
        strlcpy(bind_addr.sa_data, value, sizeof(bind_addr.sa_data));
          
#else
        strlcpy(dev.nic_device, value, sizeof(dev.nic_device));
#endif
    
    /* capture outgoing packages? */
    else if (!strcmp(key, CONF_CAP_OUT)) {
        if (atoi(value) == 1)
#ifdef linux
            outgoing = 1;
#else
            dev.out = 1;
#endif
    }
    
    /* promiscous mode? */
    else if (!strcmp(key, CONF_PROMISC)) {
        if (atoi(value) == 1)
#ifdef linux
            promisc = 1;
#else        
            dev.promisc = 1;
#endif
    }
  
    

    /* unbekannter tag? fehlermeldung und exit */
    else {
        fprintf(stderr, "config file line %d: unkown option: '%s'\n", linecount, key);
        exit(1);
    }
      
    return 0;
}

/* liest das config-file file aus und fuegt
 * die regeln der globalen rules-liste an.
 * bei fehler -> exit(1);
 * die gelesenen zeilen werden in linecount 
 * gespeichert.
 */
int
readconf(char *file) {

        FILE    *fd;
        char    *line;
        
        char    key[LEN],
                value[LEN];
        
        char    type;


    /* datei zum lesen oeffnen */
    if ((fd = fopen(file, "r")) == NULL) {
        perror("could not read config file");
        exit(-1);
    }

    clear_structs();           /* strukturen zuruecksetzen                  */
    use_system = 1;            /* default: system() benutzen                */
    log_level  = LOG_NOTICE;   /* default: LOG_NOTICE                       */
    
#ifdef linux
    memset(&bind_addr, 0, sizeof(struct sockaddr));
    promisc = 0;
    outgoing = 0;
        
    /* default device: lo */
    strlcpy(bind_addr.sa_data, "lo", sizeof(bind_addr.sa_data));
    
#else
    dev.promisc = 0;           /* default: promisc mode off                 */
    dev.out = 0;               /* default: keine outgoing packages beachten */
    
    /* default device: lo0 */
    strlcpy(dev.nic_device, "lo0", sizeof(dev.nic_device));
    
#endif
    
    type = -1;          /* aktuellen typ zuruecksetzen */
    

    /* zeilen einlesen */
    while ((line = get_line(fd)) != NULL) {
        
        /* begin neuer regel? 
         * wenn ja: alte regel ans ende der jeweiligen liste schreiben
         * type fuer die neue regel setzen, und naechste zeile lesen
         */
        
        if (!strcmp(line, CONF_TCP_TAG)) {
            append_list(type);
            type = TCP;
            continue;
        }
        
        else if (!strcmp(line, CONF_UDP_TAG)) {
            append_list(type);
            type = UDP;
            continue;
        }
        
        else if (!strcmp(line, CONF_ICMP_TAG)) {
            append_list(type);
            type = ICMP;
            continue;
        }
        
        
        /* falscher tag?, fehlermeldung ausgeben und abbrechen */        
        else if (*line == '[') {
            fprintf(stderr, "unexpected tag '%s'  near line %d\n", 
                    line, linecount);
            exit(1);
        }
        
        
        /* noch in keinem regelblock? nach globaler einstellung suchen */
        else if (type == -1) {
            key_value(line, key, LEN, value, LEN);
            global_pref(key, value); 
        }
        
        /* ansonsten, key/value auslesen, und in temporaere-regelstruktur */
        /* schreiben */
        else {
            key_value(line, key, LEN, value, LEN);
            add_to_list(type, key, value);
        }

    }
    /* und zum schluss die letzte gelesene regel anhaengen */
    append_list(type);
  

    return 0;
}

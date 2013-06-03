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


/* linked_lists.c - funktionen fuer die verketteten listen.
 * februar 2001 - Chris Aumann <c.aumann@gmx.de>
 * 
 * fuer entren -  <http://entren.sourceforge.net/>
 * 
 */



/* add_tcp_rule() - fuegt eine neue tcp-regel an die liste an
 *
 * nimmt die werte der argumente, und setzt sie als neue regel
 * ans ende der verketteten tcp-liste
 *
 *  NULL (fuer char *) und -1 (char, int) fuer keinen wert.
 *
 */
void 
add_tcp_rule (in_addr_t sip, in_addr_t dip,    /* source und dest ip */
        char not_sip, char not_dip,            /* not-flags */
        in_port_t sport, in_port_t dport,   /* source und dest port */
        char not_sport, char not_dport, /* not flags */
        char syn, char ack, char rst,     /* tcp flags */
        char fin, char psh, char urg,     /* tcp flags */
        char scan,                        /* portscan modus */
        char *grep,                       /* grepstring */
        char egrep, char not_grep,        /* egrep flag, not flag */
        int time,       /* zeit in der die packete eintreffen muessen */
        int count,      /* anzahl der packete die einreffen muessen */
        char *command1,                   /* system - kommando 1 */
        char *command2,                   /* system - kommando 2 */
        int sec,                          /* delay zwischen commando1 + 2 */
        char *logstr) {                   /* der string fuer syslog */
    
    
	struct tcp_rule *lz, *cur, *neu;
	
    /* allocate memory */
    neu = malloc(sizeof(struct tcp_rule));
    neu->next = NULL;   /* end of list */

    /* source und dest ip kopieren */
    neu->sip = sip;
    neu->dip = dip;
  
    /* die not flags fuer source und dest ip */
    neu->not_sip = not_sip;
    neu->not_dip = not_dip;
  
  
    /* die ports setzten */
    neu->sport = sport;
    neu->dport = dport;
  
    /* not flags fuer die ports */
    neu->not_sport = not_sport;
    neu->not_dport = not_dport;
  
  
    /* set the tcp flags */
    neu->syn = syn;     /* syn flag */
    neu->ack = ack;     /* ack flag */
    neu->rst = rst;     /* rst flag */
    neu->fin = fin;     /* fin flag */
    neu->psh = psh;     /* psh flag */
    neu->urg = urg;     /* urg flag */
  
    neu->scan = scan;   /* portscan modus? */
    neu->lastport = 0;  /* setze lastport auf null */
 

    /* speicher fuer den grepstring allocieren */
    neu->grep = malloc(strlen(grep) + 1);
    if (neu->grep)
        strcpy(neu->grep, grep);    /* string kopieren */
    else { 
    	perror("add_tcp_rule: out of memory");
    	exit(-1);    /* wenn nicht genug speicher: abbrechen */
    }
    neu->not_grep = not_grep;   /* die not flag fuer den grepsring */
  
    neu->egrep = egrep;    /* enhaelt der string einen regulaeren ausdruck? */
  
    neu->count = count;    /* vieviele packete muessen der regel entsprecen? */
    neu->true  = 0;        /* vieviele passende packete bissher? */


    /* memory fuer den string mit dem ersten kommando allocieren */
    neu->command1 = malloc(LEN);
    if (neu->command1)
        strlcpy(neu->command1, command1, LEN);    /* und den string kopieren */
    else {
    	perror("add_tcp_rule: out of memory");
    	exit(-1);    /* wenn nicht genug speicher: abbruch */
    }

    /* memory fuer den string mit dem zweiten kommando allocieren */
    neu->command2 = malloc(LEN);
    if (neu->command2)
        strlcpy(neu->command2, command2, LEN);    /* und den string kopieren */
    else {
    	perror("add_tcp_rule: out of memory");
    	exit(-1);    /* wenn nicht genug speicher: abbruch */
    }
  
  
    neu->sec = sec;     /* setzen der zeit zwischen kommando 1 und kommando 2 */
    neu->time = time;   /* die zeit in der "count" packete die der regel
                         * entsprechen, eintreffen muessen 
                         */
  
    neu->first = 1;     /* erster durchgang ( zum setzen der zeit benoetigt ) */
  
    /* speicher fuer den logstring fuer syslog allocieren */
    neu->logstr = malloc(LEN);
    if (neu->logstr)
        strlcpy(neu->logstr, logstr, LEN);    /* und den string kopieren */
    else {
    	perror("add_tcp_rule: out of memory");
    	exit(-1);    /* wenn nicht genug speicher: abbruch */
    }

    /* die neue regel ans ende der liste anfuegen */
    if (tcp_rules) {
        for(lz = tcp_rules; lz; lz = lz->next)    /* gehe ans ende der liste */
            cur = lz;        
            cur->next = neu;
	}
	else
        tcp_rules = neu;    /* alte liste ersetzen */
	

    return;
}





/* add_udp_rule() - fuegt eine neue udp-regel an die liste an
 *
 * nimmt die werte der argumente, und setzt sie als neue regel
 * ans ende der verketteten udp-liste
 *
 *  NULL (fuer char *) und -1 (char, int) fuer keinen wert.
 *
 */
void
add_udp_rule(in_addr_t sip, in_addr_t dip,      /* source und dest ip */
        char not_sip, char not_dip,     /* not-flags */
        in_port_t sport, in_port_t dport,           /* source und dest port */
        char not_sport, char not_dport, /* not-flags */
        char *grep,                       /* grepstring */
        char egrep, char not_grep,        /* egrep flag, not flag */
        int time,     /* zeit in der die packete eintreffen muessen */
        int count,    /* anzahl der packete die einreffen muessen */
        char *command1,                   /* kommando 1 */
        char *command2,                   /* kommando 2 */
        int sec,                          /* delay zwischen commando1 + 2 */
        char *logstr) {                   /* der string fuer syslog */  
        
        
        
	struct udp_rule *lz, *cur, *neu;

    /* allocate memory */
    neu = malloc(sizeof(struct udp_rule));
    neu->next = NULL;     /* end of list */


    /* source und dest ip kopieren */
    neu->sip = sip;
    neu->dip = dip;

    /* die not-flags fuer source/dest ip setzten */
    neu->not_sip = not_sip;
    neu->not_dip = not_dip;
  
  
    /* setze die ports */
    neu->sport = sport;
    neu->dport = dport;
  
    /* und die not flags fuer die ports */
    neu->not_sport = not_sport;
    neu->not_dport = not_dport;

    
    /* speicher fuer den grepstring fuer syslog allocieren */
    neu->grep = malloc(strlen(grep) + 1);
    if (neu->grep)
        strcpy(neu->grep, grep);    /* und den string kopieren */
    else {
	perror("add_udp_rule: out of memory");
	exit(-1);    /* wenn nicht genug speicher: abbruch */
    }
    neu->not_grep = not_grep;    /* und die not flag fuer den string */
  
    neu->egrep = egrep;   /* ist der grepstring ein regulaerer ausdruck? */
  
    neu->count = count;  
    neu->true  = 0;      
    
  
    /* allocate memory and copy string */
    neu->command1 = malloc(LEN);
    if (neu->command1)
        strlcpy(neu->command1, command1, LEN);
    else {
    	perror("add_udp_rule: out of memory");
    	exit(-1);
    }
    /* allocate memory and copy string */
    neu->command2 = malloc(LEN);
    if (neu->command2)
        strlcpy(neu->command2, command2, LEN);
    else {
    	perror("add_udp_rule: out of memory");
    	exit(-1);
    }
  
    neu->sec = sec;     /* setzen der zeit zwischen kommando 1 und kommando 2 */
    neu->time = time;   /* die zeit in der "count" packete die der regel
                         * entsprechen, eintreffen muessen 
                         */
  
    neu->first = 1;     /* erster durchgang ( zum setzen der zeit benoetigt ) */
  
  
    /* speicher fuer den logstring fuer syslog allocieren */
    neu->logstr = malloc(LEN);
    if (neu->logstr)
        strlcpy(neu->logstr, logstr, LEN);    /* und den string kopieren */
    else {
    	perror("add_udp_rule: out of memory");
    	exit(-1);    /* wenn nicht genug speicher: abbrechen */
    }


    /* die neue regel ans ende der liste anfuegen */
    if (udp_rules) {
        for(lz = udp_rules; lz; lz = lz->next)    /* bis ans ende durchgehn */
            cur = lz;
            cur->next = neu;
	}
	else
        udp_rules = neu;    /* alte regel-liste ersetzten */



    return;
}




/* add_icmp_rule() - fuegt eine neue icmp-regel an die liste an
 *
 * nimmt die werte der argumente, und setzt sie als neue regel
 * ans ende der verketteten icmp-liste
 *
 *  NULL (fuer char *) und -1 (char, int) fuer keinen wert.
 *
 */        
void
add_icmp_rule(in_addr_t sip, in_addr_t dip,  /* source und dest ip */
        char not_sip, char not_dip,  /* not-flags */
        char type[ICMPTYPELEN],        /* array fuer die ICMP-types. */
        char *grep, char egrep,        /* grepstring */
        char not_grep,                 /* egrep flag, not flag */
        int time,     /* zeit in der die packete eintreffen muessen */
        int count,    /* anzahl der packete die einreffen muessen */
        char *command1,                /* kommando 1 */
        char *command2,                /* kommando 2 */
        int sec,                       /* delay zwischen commando1 + 2 */
        char *logstr) {                /* der string fuer syslog */  
        

	struct icmp_rule *lz, *cur, *neu;
        int    i;


    /* speicher fuer die neue regel allocieren */
    neu = malloc(sizeof(struct icmp_rule));
    neu->next = NULL;

    /* source und dest ip kopieren */
    neu->sip = sip;
    neu->dip = dip;

    /* die not flags fuer die ips kopieren */
    neu->not_sip = not_sip;
    neu->not_dip = not_dip;
  
  
    /* den icmp-type array element fuer element uebertragen */
    for (i = 0; i <= ICMPTYPELEN; i++)
        neu->type[i] = type[i];
  
    
    /* speicher fuer den grepstring allocieren */
    neu->grep = malloc(strlen(grep) + 1);
    if (neu->grep)
        strcpy(neu->grep, grep);    /* und den string kopieren */
    else {
    	perror("add_icmp_rule: out of memory");
    	exit(-1);    /* wenn nicht genug speicher: abbruch */
    }
    neu->not_grep = not_grep;     /* und die not-flag */
  
    neu->egrep = egrep;   /* ist der grepstring ein regulaerer ausdruck? */
  
    neu->sec = sec;     /* setzen der zeit zwischen kommando 1 und kommando 2 */
    neu->time = time;   /* die zeit in der "count" packete die der regel
                         * entsprechen, eintreffen muessen 
                         */
  
    neu->first = 1;     /* erster durchgang ( zum setzen der zeit benoetigt ) */
    
  
    /* speicher fuer den string mit dem ersten kommando allocieren */
    neu->command1 = malloc(LEN);
    if (neu->command1)
        strlcpy(neu->command1, command1, LEN);    /* und den string kopieren */
    else {
    	perror("add_icmp_rule: out of memory");
    	exit(-1);    /* wenn nicht genug speicher: abbruch */
    }
    
    /* speicher fuer den string mit dem zweiten kommando allocieren */
    neu->command2 = malloc(LEN);
    if (neu->command2)
        strlcpy(neu->command2, command2, LEN);    /* und den string kopieren */
    else {
    	perror("add_icmp_rule: out of memory");
    	exit(-1);    /* wenn nicht genug speicher: abbruch */
    }


    /* speicher fuer den logstring allocieren */
    neu->logstr = malloc(LEN);
    if (neu->logstr)
        strlcpy(neu->logstr, logstr, LEN);    /* string kopieren */
    else {
    	perror("add_icmp_rule: out of memory");
    	exit(-1);    /* wenn nicht genug speicher: abbruch */
    }


    /* neue regel ans ende der liste anfuegen */
    if (icmp_rules) {
        for(lz = icmp_rules; lz; lz = lz->next)
            cur = lz;
            cur->next = neu;
	}
	else
        icmp_rules = neu;    /* alte regel-liste ersetzen */


  return;
}



/*  print_rules() - gibt die aktuellen regel-listen aus */
void
print_rules(void) {

	struct udp_rule  *udp;
        struct tcp_rule  *tcp;
        struct icmp_rule *icmp;
        
        struct in_addr tmp;

  printf("tcp rules:\n");
  for(tcp = tcp_rules; tcp; tcp = tcp->next) {
        tmp.s_addr = tcp->sip;
        printf("\tsource_ip: %s%s\n", (tcp->not_sip) ? "!" : "", inet_ntoa(tmp));
        tmp.s_addr = tcp->dip;
        printf("\tdest_ip %s%s\n\n", (tcp->not_dip) ? "!" : "", inet_ntoa(tmp));
        printf("\tsource port: %s%d\n\tdest port: %s%d\n\n", (tcp->not_sport) ? "!" : "", htons(tcp->sport), (tcp->not_sport) ? "!" : "", htons(tcp->dport));
        printf("\ttcp flags:\n\t\tsyn=%d ack=%d rst=%d fin=%d psh=%d urg=%d\n\n", tcp->syn, tcp->ack, tcp->rst, tcp->fin, tcp->psh, tcp->urg);
        printf("\tportscan mode: %s\n", (tcp->scan) ? "yes" : "no");
        printf("\tgrep string: '%s'%s%s\n", tcp->grep, (tcp->not_grep) ? " (not)" : "", (tcp->egrep) ? " (egrep)" : "");
        printf("\ttime: %dsec\n", tcp->time);
        printf("\tcount: %d\n", tcp->count);
        printf("\tcommand1: %s\n", tcp->command1);
        printf("\tcommand2: %s\n", tcp->command2);
        printf("\tseconds: %d\n\n", tcp->sec);
        printf("\tlogstring: %s\n", tcp->logstr);
        printf("\n\t----------------------------\n\n");
  }
  
  printf("udp rules:\n");
  for(udp = udp_rules; udp; udp = udp->next) {
        tmp.s_addr = udp->sip;
        printf("\tsource_ip: %s%s\n", (udp->not_sip) ? "!" : "", inet_ntoa(tmp));
        tmp.s_addr = udp->dip;
        printf("\tdest_ip %s%s\n\n", (udp->not_dip) ? "!" : "", inet_ntoa(tmp));
        printf("\tsource port: %s%d\n\tdest port: %s%d\n\n", (udp->not_sport) ? "!" : "", htons(udp->sport), (udp->not_sport) ? "!" : "", htons(udp->dport));
        printf("\tgrep string: '%s'%s%s\n", udp->grep, (udp->not_grep) ? " (not)" : "", (udp->egrep) ? " (egrep)" : "");
        printf("\tcount: %d\n", udp->count);
        printf("\ttime: %dsec\n", udp->time);
        printf("\tcommand1: %s\n", udp->command1);
        printf("\tcommand2: %s\n", udp->command2);
        printf("\tseconds: %d\n\n", udp->sec);
        printf("\tlogstring: %s\n", udp->logstr);
        printf("\n\t----------------------------\n\n");
  }
  
  printf("icmp rules:\n");
  for(icmp = icmp_rules; icmp; icmp = icmp->next) {
        tmp.s_addr = icmp->sip;
        printf("\tsource_ip: %s%s\n", (icmp->not_sip) ? "!" : "", inet_ntoa(tmp));
        tmp.s_addr = icmp->dip;
        printf("\tdest_ip %s%s\n\n", (icmp->not_dip) ? "!" : "", inet_ntoa(tmp));
        printf("\tgrep string: '%s'%s%s\n", icmp->grep, (icmp->not_grep) ? " (not)" : "", (icmp->egrep) ? " (egrep)" : "");
        printf("\ttime: %dsec\n", icmp->time);
        printf("\tcount: %d\n", icmp->count);
        printf("\tcommand1: %s\n", icmp->command1);
        printf("\tcommand2: %s\n", icmp->command2);
        printf("\tseconds: %d\n\n", icmp->sec);
        printf("\tlogstring: %s\n", icmp->logstr);
        printf("\n\t----------------------------\n\n");
  
  
  }
}

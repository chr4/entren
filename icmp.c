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

/* ersetzt die schluesselwoerter in logstr
 * durch die aktuellen werte die in den argumenten
 * angegeben werden
 */
int
icmp_make_logstr(char *logstr, int len, 
                char *s_ip, char *d_ip,
                char type,
                char *grep, char *data) {
                
        char    tmp[LEN];
        time_t  ticks;
        
    /* aktuelle systemzeit hohlen */        
    ticks = time(NULL);
    snprintf(tmp, sizeof(tmp), "%s", ctime(&ticks));
    cut_crlf(tmp);
    strsub(logstr, GET_TIME, tmp, len);
  
    strsub(logstr, GET_SIP, s_ip, len);
    strsub(logstr, GET_DIP, d_ip, len);


    /* icmp type nach nummer in string umwandeln und in tmp speichern */
    /* soweit moeglich, ansonsten "unkown icmp type %d" in tmp speichern */
    switch (type) {
  
        case 0:  snprintf(tmp, sizeof(tmp), "echo-reply"); break;
        case 3:  snprintf(tmp, sizeof(tmp), "dest unreach"); break;
        case 4:  snprintf(tmp, sizeof(tmp), "source quench"); break;
        case 5:  snprintf(tmp, sizeof(tmp), "redirect"); break;
        case 6:  snprintf(tmp, sizeof(tmp), "alternate host address"); break;
        case 8:  snprintf(tmp, sizeof(tmp), "echo-request"); break;
        case 9:  snprintf(tmp, sizeof(tmp), "router advertisement"); break;
        case 10: snprintf(tmp, sizeof(tmp), "router selection"); break;
        case 11: snprintf(tmp, sizeof(tmp), "time exceeded"); break;
        case 12: snprintf(tmp, sizeof(tmp), "parameter problem"); break;
        case 13: snprintf(tmp, sizeof(tmp), "timestamp request"); break;
        case 14: snprintf(tmp, sizeof(tmp), "timestamp reply"); break;
        case 15: snprintf(tmp, sizeof(tmp), "information request"); break;
        case 16: snprintf(tmp, sizeof(tmp), "information reply"); break;
        case 17: snprintf(tmp, sizeof(tmp), "addres mask request"); break;
        case 18: snprintf(tmp, sizeof(tmp), "address mask reply"); break;
        case 30: snprintf(tmp, sizeof(tmp), "traceroute"); break;
        
        default: snprintf(tmp, sizeof(tmp), "unknown icmp type (%d)", type); break;
    }
  
    strsub(logstr, GET_ICMP_TYPE, tmp, len);


    if(strlen(grep))    /* grepstring vorhanden? */
        strsub(logstr, GET_GREPSTRING, grep, len);
    else
        strsub(logstr, GET_GREPSTRING, "", len);
  
  
    strsub(logstr, GET_DATA, data, len);

    return 0;
}


/* checkt ein packet nach den gespeicherten regeln
 * wenn der count fuer eine regel ueberschritten ist
 * werden die angegebenen komandos ausgefuehrt
 * und der logstring nach syslog geschrieben
 */
int
icmp_log (struct ip *iph, struct icmp *icmph, char *data) {

        struct icmp_rule  *icmpr;
        char    log[LEN];
        char    tmp[30];        
        
        pid_t   pid;
        

    /* kopie der orginal regeln erstellen, und einen regeleintrag */
    /* nach dem anderen durchlaufen */
    for(icmpr = icmp_rules; icmpr; icmpr = icmpr->next) {

        if (icmpr->sip) {    /* source ip gesetzt? */
            if (icmpr->not_sip) {    /* umkehr flag gesetzt? */
                        
                /* ip vergleich, wenn true, regel */
                /* verwerfen (notflag gesetzt)    */
                if (icmpr->sip == iph->ip_src.s_addr)
                    continue;
            }
            
            /* wenn ip true weiter (keine umkehrflag) */
            else if (icmpr->sip != iph->ip_src.s_addr)
                continue;
        }
        
        if (icmpr->dip) {    /* dest ip vergleichen */
            if (icmpr->not_dip) {
                if (icmpr->dip == iph->ip_dst.s_addr)
                    continue;
            }
            else if (icmpr->dip != iph->ip_dst.s_addr)
                continue;
        }

        /* (unfertige/unausgereifte) methode */
        /* vergleicht aus einem array */
        /* char icmp_type[ICMPTYPELEN]; */
        /* ist der wert aus icmp_type[icmp-typ-im-header] */
        /* true, weiter, ansonsten naechste regel bearbeiten */
        if (icmph->icmp_type <= ICMPTYPELEN)
            if (!icmpr->type[icmph->icmp_type])
                continue;

        /* der string/regulaere ausdruck zum greppen */
        if (strlen(icmpr->grep)) {    /* string vorhanden? */
        
            /* negativ flag gesetzt? wenn ja, und */
            /* string vorhanden/regulaerer ausdruck */
            /* true, continue */
            if (icmpr->not_grep) {
                
                /* ist der string ein regulaerer ausdruck? */
                if (icmpr->egrep != 0) {
                    if(strstr(data, icmpr->grep) != NULL)
                        continue;
                }
                /* wenn ja, regex funktionen rufen */
                else {
                    if(!regex_match(data, icmpr->grep))
                        continue;
                }
            }
            
            /* negativ flag nicht gesetzt, wenn der */
            /* string/regulaere ausdruck true, dann weiter */
            else {
                
                /* string ein regulaerer ausdruck? */
                if (icmpr->egrep != 0) {
                    
                    /* kein regex, suchen nach "string" */
                    if(strstr(data, icmpr->grep) == NULL)
                        continue;
                }
                /* regulaerer ausdurck */
                else {
                    if(regex_match(data, icmpr->grep))
                        continue;
                }
           }
        }

        /* erstes packet das der regel entspricht? */
        /* wenn ja, aktuelle zeit speichern */
        if (icmpr->first) {
            icmpr->first = 0;    /* flag zuruecksetzen */
            icmpr->start_time = time(NULL); /* save timestamp */
        }
        
        /* ansonsten zeit checken, wenn die sekunden */
        /* in "time" ueberschritten sind, regel zuruecksetzten */        
        else 
            /* check timestamp */
            if (icmpr->start_time + icmpr->time <= time(NULL)) { 
                icmpr->first = 1;    /* flag setzen */    
                continue;
            }
        
        /* zaehler fuer gefundene packete erhoehen */   
        icmpr->true++;
        
        /* angegebene anzahl der packete empfangen? */
        /* wenn ja, reaktionen starten */
        if (icmpr->count <= icmpr->true) {

            icmpr->true = 0;    /* zaehler fuer gefundene packete = 0 */
            icmpr->first = 1;   /* first-time flag zuruecksetzen */ 
            
            /* dest ip temporaer zwischenspeichern */
            strlcpy(tmp, inet_ntoa(iph->ip_dst), sizeof(tmp));

            if (strlen(icmpr->logstr)) {
                strlcpy(log, icmpr->logstr, LEN);
                icmp_make_logstr(log, sizeof(log),
                                 inet_ntoa(iph->ip_src), tmp,
                                 icmph->icmp_type,
                                 icmpr->grep, data);                    

                /* wenn im foreground modus gestartet */
                /* logstring nicht nach syslog */
                /* sondern stdout */
                if (foreground)
                    puts(log);
                else                
                    syslog(log_level, log);
                }   
            }           
                    
            /* wenn command1 oder command2 gesetzt, forken */
    	    if (strlen(icmpr->command1) || strlen(icmpr->command2)) {
    	                            
                /* kindprozess starten */
                if ((pid = vfork()) == 0) {
                    
                        char    cmd1[LEN];
                        char    cmd2[LEN];
    
    
                    /* Zombies verhindern */
                    if (vfork() > 0)
                        exit(0);
                            
                    /* command 1 */
                    if (strlen(icmpr->command1)) {

                        /* string vorbeireiten */                        
                        strlcpy(cmd1, icmpr->command1, LEN);
                        icmp_make_logstr(cmd1, sizeof(cmd1),
                                         inet_ntoa(iph->ip_src), tmp,
                                         icmph->icmp_type,
                                         icmpr->grep, data);                    
                        
                        exec_cmd(cmd1);     /* erstes kommando rufen */
                    }
                     
                    /* command 2 */   
                    if (strlen(icmpr->command2)) {
                        sleep(icmpr->sec);    /* angegebenen delay warten */                    
                        
                        /* string vorbereiten */
                        strlcpy(cmd2, icmpr->command2, LEN);
                        icmp_make_logstr(cmd2, sizeof(cmd2),
                                         inet_ntoa(iph->ip_src), tmp,
                                         icmph->icmp_type,
                                         icmpr->grep, data);    
                        
                        exec_cmd(cmd2);     /* zweites kommando aufrufen */
                    }
                        
                    exit(0);    /* kindprozess beenden */
                }
                
            waitpid(pid, NULL, 0);                
            
            }
    }

    return 0;
}

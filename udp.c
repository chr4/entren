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
udp_make_logstr(char *logstr, int len, 
                char *s_ip, char *d_ip,
                int s_port, int d_port,
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

    snprintf(tmp, sizeof(tmp), "%d", s_port);
    strsub(logstr, GET_SPORT, tmp, len);

    snprintf(tmp, sizeof(tmp), "%d", d_port);
    strsub(logstr, GET_DPORT, tmp, len);

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
udp_log (struct ip *iph, struct udphdr *udph, char *data) {

          struct udp_rule  *udpr;
          char    log[LEN];
          char    tmp[30];

          pid_t   pid;


    /* kopie der orginal regeln erstellen, und einen regeleintrag */
    /* nach dem anderen durchlaufen */
    for(udpr = udp_rules; udpr; udpr = udpr->next) {

        if (udpr->sip) {    /* ip gesetzt? */
            if (udpr->not_sip) { /* negativ flag gesetzt ? */
            
                /* ip vergleich, wenn true, regel */
                /* verwerfen (notflag gesetzt)    */
                if (udpr->sip == iph->ip_src.s_addr) 
                    continue;
            }
            /* wenn ip true weiter (keine notflag */
            else if (udpr->sip == iph->ip_src.s_addr)
                continue;
        }

        if (udpr->dip) {   /* dest ip vergleichen */
            if (udpr->not_dip) {
                if (udpr->dip == iph->ip_dst.s_addr)
                    continue;
            }
            else if (udpr->dip != iph->ip_dst.s_addr)
                continue;
        }

        if (udpr->dport) {  /* dest port gesetzt? */

            /* umkehr flag gesetzt? */
            /* wenn ja, und portvergleich true */
            /* continue */
            if (udpr->not_dport) {
                 if (udpr->dport == udph->uh_dport)
                     continue;
            }
              
            /* wenn umkehr flag nicht gesetzt, */
            /* und portvergleich true, weiter  */
            else if (!(udpr->dport == udph->uh_dport))
                 continue;
        }
        
        /* das ganze nochmal mit dem source port */
        if (udpr->sport) {
            if (udpr->not_sport) {
                 if (udpr->sport == udph->uh_sport)
                      continue;
            }
            else if (!(udpr->sport == udph->uh_sport))
                 continue;
        }


        /* der string/regulaere ausdruck zum greppen */
        if (strlen(udpr->grep)) {    /* string vorhanden? */

            /* negativ flag gesetzt? wenn ja, und */
            /* string vorhanden/regulaerer ausdruck */
            /* true, continue */
            if (udpr->not_grep) {

                 /* ist der string ein regulaerer ausdruck? */
                 if (udpr->egrep != 0) {
                      if(strstr(data, udpr->grep) != NULL)
                          continue;
                 }
                 /* wenn ja, regex funktionen rufen */
                 else {
                     if(!regex_match(data, udpr->grep))
                         continue;
                 }
            }
            
            /* negativ flag nicht gesetzt, wenn der */
            /* string/regulaere ausdruck true, dann weiter */
            else {
                
                /* string ein regulaerer ausdruck? */
                if (udpr->egrep != 0) {
                    
                    /* kein regex, suchen nach "string" */
                    if(strstr(data, udpr->grep) == NULL)
                        continue;
                    }
                    
                    /* regulaerer ausdurck */
                    else {
                        if(regex_match(data, udpr->grep))
                            continue;
                    }

                }
        }
        
        
        /* erstes packet das der regel entspricht? */
        /* wenn ja, aktuelle zeit speichern */
        if (udpr->first) {
            udpr->first = 0;    /* flag zuruecksetzen */
            udpr->start_time = time(NULL); /* save timestamp */
        }
        
        /* ansonsten zeit checken, wenn die sekunden */
        /* in "time" ueberschritten sind, regel zuruecksetzten */
        else 
            /* check timestamp */
            if (udpr->start_time + udpr->time <= time(NULL)) { 
                udpr->first = 1;    /* flag setzen */
                continue;
            }

        /* zaehler fuer gefundene packete erhoehen */
        udpr->true++;
        
        /* angegebene anzahl der packete empfangen? */
        /* wenn ja, reaktionen starten */
        if (udpr->count <= udpr->true) {
            
            udpr->true = 0;    /* zaehler fuer gefundene packete = 0 */
            udpr->first = 1;   /* first-time flag zuruecksetzen */        
            

            /* dest ip demporaer zwischenspeichern */
            strlcpy(tmp, inet_ntoa(iph->ip_dst), sizeof(tmp));

            if (strlen(udpr->logstr)) {
                strlcpy(log, udpr->logstr, LEN);
                udp_make_logstr(log, sizeof(log),
    	                        inet_ntoa(iph->ip_src), tmp,
                                htons(udph->uh_sport), htons(udph->uh_dport),
                                udpr->grep, data);
                                
                /* wenn im foreground modus gestartet */
                /* logstring nicht nach syslog */
                /* sondern stdout */
                if (foreground)
                    puts(log);
                else
                    syslog(log_level, log);
            }
            
            /* wenn command1 oder command2 gesetzt, forken */    	    
    	    if (strlen(udpr->command1) || strlen(udpr->command2)) {
    	        
                /* kindprozess starten */
                if ((pid = vfork()) == 0) {
                    
                        char    cmd1[LEN];
                        char    cmd2[LEN];
    
    
                    /* Zombies verhindern */
                    if (vfork() > 0)
                        exit(0);
                                            
                    /* commando 1 */   
                    if (strlen(udpr->command1)) {
                        
                        /* string vorbereiten */
                        strlcpy(cmd1, udpr->command1, LEN);
                        udp_make_logstr(cmd1, sizeof(cmd1),
                                        inet_ntoa(iph->ip_src), tmp,
                                        htons(udph->uh_sport), htons(udph->uh_dport),
                                        udpr->grep, data);
                                        
                        exec_cmd(cmd1);    /* erstes kommando rufen */
                    }
                     
                    /* commando 2 */   
                    if (strlen(udpr->command2)) {
                        sleep(udpr->sec);    /* angegebenen delay warten */
                        
                        /* string vorbereiten */
                        strlcpy(cmd2, udpr->command2, LEN);
                        udp_make_logstr(cmd2, sizeof(cmd2),
                                        inet_ntoa(iph->ip_src), tmp,
                                        htons(udph->uh_sport), htons(udph->uh_dport),
                                        udpr->grep, data);
                                    
                        exec_cmd(cmd2);    /* zweites kommando aufrufen */
                    }
                          
                    exit(0);    /* kindprozess beenden */
                }
                
            waitpid(pid, NULL, 0);
                            
            }
        }
        

    }


    return 0;

}

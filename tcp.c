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
tcp_make_logstr(char *logstr, int len, 
                char *s_ip, char *d_ip,
                int s_port, int d_port,
                char syn, char ack, char fin,
                char rst, char psh, char urg,
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

    strlcpy(tmp, "tcp flags: ", sizeof(tmp));
    
    /* string mit allen gesetzten tcp-flags erstellen */
    if (syn)
        strlcat(tmp, "SYN ", sizeof(tmp));
    if (ack)
        strlcat(tmp, "ACK ", sizeof(tmp));
    if (rst)
        strlcat(tmp, "RST ", sizeof(tmp));
    if (fin)
        strlcat(tmp, "FIN ", sizeof(tmp));
    if (urg)
        strlcat(tmp, "URG ", sizeof(tmp));
    if (psh)
        strlcat(tmp, "PSH ", sizeof(tmp));

    strsub(logstr, GET_TCP_FLAGS, tmp, len);

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
tcp_log (struct ip *iph, struct tcphdr *tcph, char *data) {

        struct tcp_rule  *tcpr;
        char    log[LEN];
        char    tmp[30];        

        pid_t   pid;


    /* kopie der orginal regeln erstellen, und einen regeleintrag */
    /* nach dem anderen durchlaufen */
    for(tcpr = tcp_rules; tcpr; tcpr = tcpr->next) {

        if (tcpr->sip) {    /* source ip gesetzt? */
            if (tcpr->not_sip) {    /* umkehr flag gesetzt? */
            
                /* ip vergleich, wenn true, regel */
                /* verwerfen (umkehrflag gesetzt)    */
                if (tcpr->sip == iph->ip_src.s_addr)
                     continue;
            }
            
            /* wenn ip true weiter (keine umkehrflag) */
            else if (tcpr->sip != iph->ip_src.s_addr)
                 continue;
        }
        
        if (tcpr->dip) {    /* dest ip vergleichen */
            if (tcpr->not_dip) {
                if (tcpr->dip == iph->ip_dst.s_addr)
                    continue;
            }
            else if (tcpr->dip != iph->ip_dst.s_addr)
                continue;
        }


        /* scanmode: wird zum erkennen von portscans */
        /* gebraucht. */
        /* regel nur true, wenn der dest-port dieses */
        /* packetes ein anderer ist als der im letzten */
        if (tcpr->scan) {    /* scanmode aktiviert? */
        
            /* wenn ja, und der letzte dest port */
            /* == dem jetzigen, continue */
            if (tcpr->lastport)
                if (tcph->th_dport == tcpr->lastport)
                    continue;
                    
            /* ansonsten dest port in lastport speichern */
            /* und weiter... */
            tcpr->lastport = tcph->th_dport;
        }
        

        if (tcpr->dport) {    /* dest port gesetzt? */
        
            /* umkehr flag gesetzt? */
            /* wenn ja, und portvergleich true */
            /* continue */
            if (tcpr->not_dport) {
                if (tcpr->dport == tcph->th_dport)
                    continue;
            }
            
            /* wenn umkehr flag nicht gesetzt, */
            /* und portvergleich true, weiter  */
            else if (!(tcpr->dport == tcph->th_dport))
                continue;
        }
        
        /* das ganze nochmal mit dem sourceport */
        if (tcpr->sport) {
            if (tcpr->not_sport) {
                if (tcpr->sport == tcph->th_sport)
                    continue;
            }
            else if (!(tcpr->sport == tcph->th_sport))
                continue;
        }
        

        /* die tcp-flags. */
        /* wenn nicht auf UNSET (-1) initialisiert */
        /* ueberpruefen. */
        /* 0 == darf nicht gesetzt sein */
        /* 1 == muss gesetzt sein */
        /* -1 (UNSET) == ignorieren und weiter */
                    
        if (tcpr->ack != UNSET)    /* acknowlegment */ 
            if (!(tcpr->ack == ((tcph->th_flags & TH_ACK) ? 1 : 0 )))
                continue;

        if (tcpr->psh != UNSET)    /* push */
            if (!(tcpr->psh == ((tcph->th_flags & TH_PUSH) ? 1 : 0 )))
                continue;

        if (tcpr->syn != UNSET)    /* syncronisation */ 
             if (!(tcpr->syn == ((tcph->th_flags & TH_SYN) ? 1 : 0 )))
                continue;
        
        if (tcpr->fin != UNSET)    /* final */
            if (!(tcpr->fin == ((tcph->th_flags & TH_FIN) ? 1 : 0 )))
                continue;
        
        if (tcpr->rst != UNSET)    /* reset */
            if (!(tcpr->rst == ((tcph->th_flags & TH_RST) ? 1 : 0 )))
                continue;
        
        if (tcpr->urg != UNSET)    /* urgent */
            if (!(tcpr->urg == ((tcph->th_flags & TH_URG) ? 1 : 0 )))
                continue;

        /* der string/regulaere ausdruck zum greppen */
        if (strlen(tcpr->grep)) {    /* string vorhanden? */
        
            /* negativ flag gesetzt? wenn ja, und */
            /* string vorhanden/regulaerer ausdruck */
            /* true, continue */
            if (tcpr->not_grep) {

                /* ist der string ein regulaerer ausdruck? */
                if (tcpr->egrep < 1) {
                    if(strstr(data, tcpr->grep) != NULL)
                        continue;
                }
                /* wenn ja, regex funktionen rufen */
                else {
                    if(!regex_match(data, tcpr->grep))
                        continue;
                }
            }
            
            /* negativ flag nicht gesetzt, wenn der */
            /* string/regulaere ausdruck true, dann weiter */
            else {

                /* string ein regulaerer ausdruck? */
                if (tcpr->egrep < 1) {

                    /* kein regex, suchen nach "string" */
                    if(strstr(data, tcpr->grep) == NULL)
                        continue;
                }
                
                /* regulaerer ausdurck */
                else {
                    if(regex_match(data, tcpr->grep))
                        continue;
                }

            }

        }
       
        /* erstes packet das der regel entspricht? */
        /* wenn ja, aktuelle zeit speichern */
        if (tcpr->first) {
            tcpr->first = 0;    /* flag zuruecksetzen */
            tcpr->start_time = time(NULL); /* save timestamp */
        }
        
        /* ansonsten zeit checken, wenn die sekunden */
        /* in "time" ueberschritten sind, regel zuruecksetzten */
        else   
            /* check timestamp */
            if (tcpr->start_time + tcpr->time <= time(NULL)) { 
                tcpr->first = 1;    /* flag setzen */
                    continue;
            }
            
        /* zaehler fuer gefundene packete erhoehen */        
        tcpr->true++;
        
        /* angegebene anzahl der packete empfangen? */
        /* wenn ja, reaktionen starten */
        if (tcpr->count <= tcpr->true) {

            tcpr->true = 0;    /* zaehler fuer gefundene packete = 0 */
            tcpr->first = 1;   /* first-time flag zuruecksetzen */

            /* dest ip zwischenspeichern */
            strlcpy(tmp, inet_ntoa(iph->ip_dst), sizeof(tmp));
        
            if (strlen(tcpr->logstr)) {

                /* logstring vorbereiten */
                /* (schluesselwoerter austauschen */
                strlcpy(log, tcpr->logstr, LEN);
                tcp_make_logstr(log, sizeof(log),
                                inet_ntoa(iph->ip_src), tmp,
                                htons(tcph->th_sport), 
                                htons(tcph->th_dport),
                                tcph->th_flags & TH_SYN, 
                                tcph->th_flags & TH_ACK, 
                                tcph->th_flags & TH_FIN,
                                tcph->th_flags & TH_RST, 
                                tcph->th_flags & TH_PUSH, 
                                tcph->th_flags & TH_URG,
                                tcpr->grep, data);
                    
                /* wenn foregorund modus, logging nach stdout */
                /* anstatt nach syslog */
                if (foreground)
                    puts(log);
                else
                    syslog(log_level, log);
    	    }
    	    
            /* wenn command1 oder command2 gesetzt, forken */    	    
    	    if (strlen(tcpr->command1) || strlen(tcpr->command2)) {
    	        
                /* kindprozess starten */
                if ((pid = vfork()) == 0) {
   
                        char    cmd1[LEN];
                        char    cmd2[LEN];

                    /* Zombies verhindern */
                    if (vfork() > 0)
                        exit(0);

                    /* commando 1 */                        
                    if (strlen(tcpr->command1)) {
                        
                        /* string vorbereiten */
                        strlcpy(cmd1, tcpr->command1, LEN);
                        tcp_make_logstr(cmd1, sizeof(cmd1),
                                        inet_ntoa(iph->ip_src), tmp,
                                        htons(tcph->th_sport), 
                                        htons(tcph->th_dport),
                                        tcph->th_flags & TH_SYN, 
                                        tcph->th_flags & TH_ACK, 
                                        tcph->th_flags & TH_FIN,
                                        tcph->th_flags & TH_RST, 
                                        tcph->th_flags & TH_PUSH, 
                                        tcph->th_flags & TH_URG,
                                        tcpr->grep, data);                    
                                          
                        exec_cmd(cmd1);    /* erstes kommando rufen */
                    }
                    
                    /* commando 2 */
                    if (strlen(tcpr->command2)) {
                        sleep(tcpr->sec);    /* angegebenen delay warten */
                        
                        /* string vorbereiten */
                        strlcpy(cmd2, tcpr->command2, LEN);
                        tcp_make_logstr(cmd2, sizeof(cmd2),
                                        inet_ntoa(iph->ip_src), tmp,
                                        htons(tcph->th_sport), 
                                        htons(tcph->th_dport),
                                        tcph->th_flags & TH_SYN, 
                                        tcph->th_flags & TH_ACK, 
                                        tcph->th_flags & TH_FIN,
                                        tcph->th_flags & TH_RST, 
                                        tcph->th_flags & TH_PUSH, 
                                        tcph->th_flags & TH_URG,
                                        tcpr->grep, data);
                                                        
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

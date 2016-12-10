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


/* Schneidet evt. abschliessende \n oder \r von einem String ab
 * (danke Felix)
 */
void
cut_crlf (char *stuff) {

	    char *p;

    p = strchr(stuff, '\r');
    if (p)
    	*p = '\0';

    p = strchr(stuff, '\n');
    if (p)
    	*p = '\0';
}



/* parse_args() 
 * Gibt String src als char *argv[] zurueck.
 * Wobei maximal 'max' Argumente bearbeitet werden,
 * Und für jedes Argument nicht mehr als 'len' Zeichen
 * kopiert werden.
 * (src wird beim aufruf zerstoert)
 *
 * Returnwert: Anzahl der gefundenen Argumente
 *
 * Beispiel:
 * src: commando arg1 arg2 arg3
 * parse_args(src, argv, 5);
 * argv[0]: commando
 * argv[1]: arg1
 * argv[2]: arg2
 * argv[3]: arg3
 * argv[4]: NULL
 *
 * (und wiedermal ein: Danke Felix :o) )
 */

int
parse_args(char *src, char **args, int max) {
    
        int    i;

    /* solange *src != '\0' */
    for(i = 0; (i < max - 1) && *src; i++) {

        while(*src && isspace(*src))
            src++;

        /* string in argv[i] kopieren */        
        args[i] = src;
        
        /* alles am ende dieses arguments abschneiden */
        while(*src && !isspace(*src))
            src++;
            
        /* NULL terminieren */
        if (*src)
            *(src++) = '\0';
        
    }

    /* letztes element der liste ist NULL */
    args[i] = NULL;

    /* anzahl der argumente zurückgeben */
    return i;   
}




/* teilt 'string' in 2 verschiedene strings auf
 * wobei '=' als trennzeichen verwendet wird
 * der erste teil wird in 'key' gespeichert, der 
 * zweite in 'value'. wobei maximal 'len' zeichen
 * kopiert werden.
 * evt vorhandene anfuehrende oder abschliessende
 * leerzeichen werden entfernt.
 */
int
key_value(char *string, char *key, int k_len, char *value, int v_len) {

        char    *s = string;    /* s zeigt auf string */
        int     i;

    /* evt vorhandenen string eleminieren */
    value[0] = '\0';

    no_space(s);    /* angehende leerzeichen entfernen */
    
    /* solange i kleiner als k_len, s nicht auf '=' zeigt */
    /* oder der string zuende ist ('\0'), i incrementieren */
    /* und s auf den naechsten buchstraben in "string" zeigen lassen */
    /* s in key kopieren, am ende '\0' terminieren */
    for (i = 0; i <= k_len && *s != '=' && *s != '\0'; i++, s++)
        key[i] = *s;
    key[i] = '\0';

    /* eventuelle leerzeichen am ende von "key" eleminieren */
    i--;
    for (; isspace(key[i]); key[i] = '\0', i--);

    s++;
    no_space(s);
    /* den rest des strings in value kopieren */
    strlcpy(value, s, v_len);
  
    return 0;
}


/* wenn value mit einem ! beginnt wird
 * 1 zurueckgegeben und der string nach dem !
 * in target gespeichert. (maximal werden len zeichen
 * kopiert)
 * andernfall wird value nach target kopiert und 0
 * zurueckgegeben
 */
int
not_set(char *value, char *target, int len) {

        char    *p = value;    /* p zeigt auf value */
        char     flag;

    /* wenn erstes zeichen ein ! */
    /* flag setzen, und ! uebergehen */
    if (*p == '!') {
        p++;
        flag = 1;
    }
    /* ansonsten flag = 0 */
    else
        flag = 0;
  
    /* string in target kopieren */
    strlcpy(target, p, len);

    /* flag zurueckgeben */
    return flag;
}


/* sucht in string nach matchstr.
 * wenn gefunden wird matchstr durch newstr ersetzt
 * wobei die maximale laenge von string LEN ist.
 * return: bei fehler -1 wenn nicht gefunden 0
 * ansonsten die neue laenge von string
 */
int
strsub(char *string, char *matchstr, char *newstr, int len) {

        char    retstr[LEN];
        char    *p = string;   /* p zeigt auf string */
        char    *s = retstr;   /* s auf retstr */

    /* evt. alten string eleminieren */
    memset(retstr, 0, LEN);
  
    /* notwendiger wert nicht gesetzt? */
    /* return -1 */
    if (!(string && matchstr && newstr))
        return -1;

    /* zu ersetztender string nicht */
    /* in string vorhanden? */
    /* return 0 */
    if (strstr(string, matchstr) == NULL) {
        return  0;
    }

    /* string mit hilfe von p durchlaufen */
    /* und jeden buchstaben in s (retstr) */
    /* kopieren */  
    for ( ; *p; *(s++) = *(p++) ) {
        
        /* wenn die ersten zeichen von p */
        /* == matchstr */
        if(!strncmp(p, matchstr, strlen(matchstr)) ) {
            /* matchstr in p ueberspringen */
            p += strlen(matchstr);
            /* neuen string anstelle von matchstr */
            /* an s (restr) anhaengen */
            strlcat(s, newstr, sizeof(retstr));
            /* s zeiger ueber newsstr springen lassen */
            /* und weiter */
            s += strlen(newstr);
        }
    }

    /* s nullterminiren */
    *s = '\0';
    /* string durch retstr ersetzen */
    strlcpy(string, retstr, len);
  
    /* (neue) laenge von string zurueckgeben */
    return strlen(string);
}



/* thx to: http://www.bsn.com:8080/cgi-bin/htmlman?regcomp(3C) */

/*
 * Match string against the extended regular expression in
 * pattern, treating errors as no match.
 *
 * return 0 for match, 1 for no match
 */

int
regex_match(const char *string, char *pattern) {

        int  status;
        regex_t   re;

    if (regcomp(&re, pattern, REG_EXTENDED|REG_NOSUB) != 0) {
        return -1;      /* report error */
    }
    
    status = regexec(&re, string, (size_t) 0, NULL, 0);
    regfree(&re);
    
    if (status != 0) {
        return 1;      /* report error */
    }
    
    return 0;
}


/* implementationen von strlcpy und strlcat */
/* (auf linux normalerweise nicht vorhanden */
#ifndef MIN
#define MIN(x, y)  ((x) < (y) ? (x) : (y))
#endif

#ifndef strlcpy
size_t 
strlcpy(char *dst, const char *src, size_t siz) {

        size_t n;
        size_t slen = strlen(src);
        
    if (siz) {
        if ((n = MIN(slen, siz - 1)))
            memcpy(dst, src, n);
            dst[n] = '\0';
    } 
    return(slen);
}
#endif


#ifndef strlcat
size_t 
strlcat(char *dst, const char *src, size_t siz) {

        size_t dlen = strlen(dst); /* Make sure siz is sane */
        
    if (dlen < siz - 1)
        return(dlen + strlcpy(dst + dlen, src, siz - dlen));
    else
        return(dlen + strlen(src));
}
#endif

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


/* initialize daemon mode */
int
background(void) {
  
        int pid;
        
  if ((pid = fork()) != 0)
        exit(0);
        
  setsid();
        
  signal(SIGHUP, SIG_IGN);
  if ((pid = fork()) != 0)
        exit(0);

  chdir("/");
  umask(0);

  return 0;

}


/* usage()
 * Displays a short help and determines with exit(1)
 */
void
usage(void) {

    fprintf(stderr, "usage: 'entren [args]'\n");
    fprintf(stderr, "type:  'entren --help' for help\n");
    exit(1);
}



/* print_help()
 * Displays the --help screen, and determines with exit(0)
 */
void
print_help(void) {
    
    puts("\nentren --- a traffic analyser, may also be used as an intrusion detection system");
    puts("Copyright (C) 2002  Chris Aumann <c_aumann@users.sourceforge.net>\n\n");
    puts("Verison: 0.8.4");
    
    puts("Usage: entren [args]\n\n");
    
    puts("  -h, --help                     This thing\n");
    puts("  -c, --configfile <filename>    Use <configfile> instead of /etc/entren.conf\n");
    puts("  -p, --print-rules              Just read the rules and report errors. If no");
    puts("                                 errors where found, print the rules and exit\n");
    puts("  -f, --foreground               Foreground mode, logstr goes to stdout");
    puts("                                 instead of syslog. Verbose mode.");
    
    puts("\n\nReport bugs to: <c_aumann@users.sourceforge.net>");
    puts("for the newest version, visit <http://entren.sourceforge.net/>\n");
    
    exit(0);
}     


/*******************************
 * main() 
 *******************************/
int
main (int argc, char **argv) {

        int    i;
        char   configfile[LEN];
        char   flag_print_rules;


    /* Set the default config-file (/etc/entren.conf) */
    strlcpy(configfile, DEFAULT_CONFIG_FILE, sizeof(configfile));

    /* Default: foreground mode off (run as daemon) */
    foreground = 0;

    /* Prase the command-line arguments */
    for (i = 1; i < argc; i++) {

        /* Display help */
        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h"))
            print_help();

        /* Use another config-file */
        else if (!strcmp(argv[i], "--configfile") || !strcmp(argv[i], "-c")) {
            if (argc >= i)
                /* Set the new config-file */
                strlcpy(configfile, argv[++i], sizeof(configfile));

            else    /* Not enough arguments, display usage and exit */
                usage();

        }
        
        /* foreground mode / verbose */
        else if (!strcmp(argv[i], "--foreground") || !strcmp(argv[i], "-f"))
            foreground = 1;    /* Activate foreground mode */

        else if (!strcmp(argv[i], "--print-rules") || !strcmp(argv[i], "-p"))
            flag_print_rules = 1;    /* Activate "print rules flag" */
            
        /* Unknown option */
        else {
            fprintf(stderr, "unkown option: '%s'\n\n", argv[i]);
            usage();
        }
    } 


    readconf(configfile);     /* Parse the config-file*/

    /* If --print-rules was set, display the rules and exit */    
    if (flag_print_rules) {
        print_rules(); 
        exit(0);
    }
    
    /* If running in the foreground mode, display verbose information */
    if (foreground) {
        printf("use system: %s\n", (use_system) ? "yes" : "no");
        printf("log-level: %d\n", log_level);

#ifdef linux
        printf("capture outgoing packages: %s\n", (outgoing) ? "yes" : "no");
        printf("promisc mode: %s\n", (promisc) ? "yes" : "no");
        printf("Using Device: %s\n", bind_addr.sa_data);
#endif        
    }

    if (!foreground)
        background();         /* daemon mode */
        
    /* Capture packages, and check them for the rules */        
    cap_packages();


    return 0;

}

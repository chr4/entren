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


#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "entren.h"


/* exec_cmd()
 * fuehrt ein systemkommando aus.
 *
 * (wenn globale variable use_system gesetzt
 * wird system() benutzt, ansonsten execvp() )
 *
 */
int
exec_cmd(char *s) {
    
        pid_t    pid;
        int      status;
        char    *args[MAXARG];
        char    cmd[LEN]; 
    
    if (use_system) {
        system(s);
        return 0;
    }

    strlcpy(cmd, s, LEN);
    parse_args(cmd, args, MAXARG);

    if ((pid = fork()) == 0)
        if (execvp(args[0], args) == -1)
            exit(1);

    if (pid < 0)
        return pid;

    waitpid(pid, &status, 0);

    return 0;
}

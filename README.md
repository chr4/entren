# entren

This was a C project I wrote when I was like 17, back in the days when there were no real intrusion-detection systems (I knew of).
It was written for \*BSD and Linux back then, and I just tried typing `make` on my OS X El Capitan, and **whoohoo** it just compiled fine and worked out of the box.

This kind of fascinated me, so I uploaded it to Github.

## Usage

```shell
make
./entren -c entren.conf -f
```

## Documentation

See [entren.conf](https://github.com/chr4/entren/blob/master/entren.conf) for a simple example, [entren.conf.sample](https://github.com/chr4/entren/blob/master/entren.conf.sample) for the full documentation.

```
$ ./entren --help

entren --- a traffic analyser, may also be used as an intrusion detection system
Copyright (C) 2002  Chris Aumann <c_aumann@users.sourceforge.net>


Verison: 0.8.4
Usage: entren [args]


  -h, --help                     This thing

  -c, --configfile <filename>    Use <configfile> instead of /etc/entren.conf

  -p, --print-rules              Just read the rules and report errors. If no
                                 errors where found, print the rules and exit

  -f, --foreground               Foreground mode, logstr goes to stdout
                                 instead of syslog. Verbose mode.


Report bugs to: <c_aumann@users.sourceforge.net>
for the newest version, visit <http://entren.sourceforge.net/>
```

# Makefile for entren

CC=gcc
CC_OPTIONS=-Wall


entren : main.o cap_packages.o open_bpf.o exec_cmd.o linked_lists.o str_func.o tcp.o udp.o icmp.o readconf.o
	$(CC) $(CC_OPTIONS) -o entren main.o cap_packages.o exec_cmd.o open_bpf.o linked_lists.o str_func.o tcp.o udp.o icmp.o readconf.o

main.o : main.c
	$(CC) $(CC_OPTIONS) -c main.c
	
cap_packages.o : cap_packages.c
	$(CC) $(CC_OPTIONS) -c cap_packages.c

open_bpf.o : open_bpf.c
	$(CC) $(CC_OPTIONS) -c open_bpf.c

exec_cmd.o : exec_cmd.c
	$(CC) $(CC_OPTIONS) -c exec_cmd.c
	
linked_lists.o : linked_lists.c
	$(CC) $(CC_OPTIONS) -c linked_lists.c

str_func.o : str_func.c
	$(CC) $(CC_OPTIONS) -c str_func.c

tcp.o : tcp.c
	$(CC) $(CC_OPTIONS) -c tcp.c

udp.o : udp.c
	$(CC) $(CC_OPTIONS) -c udp.c

icmp.o : icmp.c
	$(CC) $(CC_OPTIONS) -c icmp.c

readconf.o : readconf.c
	$(CC) $(CC_OPTIONS) -c readconf.c





clean :
	rm -f *.o entren



install : 
	cp entren /usr/sbin
	chmod 700 /usr/sbin/entren
	cp entren.conf.sample /etc/entren.conf
	chmod 600 /etc/entren.conf

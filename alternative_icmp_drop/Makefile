all:
	clang -O2 -g -target bpf -c main.c -o main.o

load:
	sudo ip -force link set dev lo xdp obj main.o sec xdp verbose	

unload:
	sudo ip link set dev lo xdp off

show:
	ip -d link show dev lo

test:
	ping -c 4 127.0.0.1

dump:
	sudo tcpdump -i lo icmp &

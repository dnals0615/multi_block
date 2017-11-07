all : multi_block

multi_block : main.o
	gcc -o multi_block main.o -lpcap -lnetfilter_queue

main.o : main.c
	gcc -c -o main.o main.c -lnetfilter_queue -lpcap

clean : 
	rm *.o multi_block

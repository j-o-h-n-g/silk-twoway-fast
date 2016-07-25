packlogic-twoway-fast.so: packlogic-twoway-fast.o patricia.o
	gcc -g -shared -Wl,-soname,packlogic-twoway-fast.so -o packlogic-twoway-fast.so packlogic-twoway-fast.o patricia.o -lc -Wall

packlogic-twoway-fast.o: packlogic-twoway-fast.c
	gcc -fPIC -c -o packlogic-twoway-fast.o packlogic-twoway-fast.c -Wall -g

patricia.o: patricia.c
	gcc -fPIC -c -o patricia.o patricia.c -g

clean:
	rm packlogic-twoway-fast.so packlogic-twoway-fast.o patricia.o

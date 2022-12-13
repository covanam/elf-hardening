main: test.cpp disasm.cpp disasm.h
	g++ -g test.cpp disasm.cpp -IELFIO -lcapstone -lkeystone -o main

clean:
	rm *.o main
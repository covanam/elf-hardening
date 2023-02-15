harden: test.cpp disasm.cpp disasm.h
	g++ -g test.cpp disasm.cpp -IELFIO -lcapstone -lkeystone -o harden

clean:
	rm *.o harden
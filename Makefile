CPPFLAGS = -g -IELFIO -lcapstone -lkeystone

harden: test.o disasm.o analysis.o disasm.h analysis.h
	g++ -g test.o disasm.o analysis.o $(CPPFLAGS) -o harden

clean:
	rm *.o harden
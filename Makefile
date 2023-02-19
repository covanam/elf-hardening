CPPFLAGS = -g -IELFIO -lcapstone -lkeystone

harden: test.o disasm.o cfg.o disasm.h cfg.h
	g++ -g test.o disasm.o cfg.o $(CPPFLAGS) -o harden

clean:
	rm *.o harden
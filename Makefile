CPPFLAGS = -g -IELFIO -lcapstone -lkeystone

harden: test.o disasm.o cfg.o liveness.o disasm.h cfg.h liveness.h
	g++ -g test.o disasm.o cfg.o liveness.o $(CPPFLAGS) -o harden

clean:
	rm *.o harden
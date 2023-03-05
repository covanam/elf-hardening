CXXFLAGS = -g -IELFIO -lcapstone -lkeystone

harden: disasm.o cfg.o analysis.o reg-alloc.o test.o
	g++ $^ $(CXXFLAGS) -o $@

disasm.o: disasm.cpp disasm.h
	g++ -c $(CXXFLAGS) $< -o $@

cfg.o: cfg.cpp cfg.h disasm.h
	g++ -c $(CXXFLAGS) $< -o $@

analysis.o: analysis.cpp analysis.h cfg.h disasm.h
	g++ -c $(CXXFLAGS) $< -o $@

reg-alloc.o: reg-alloc.cpp reg-alloc.h analysis.h cfg.h disasm.h
	g++ -c $(CXXFLAGS) $< -o $@

no_change: disasm.o test_no_change.o
	g++ $^ $(CXXFLAGS) -o harden

test_cfg: disasm.o test_cfg.cpp cfg.o
	g++ $^ $(CXXFLAGS) -o harden

test_liveness: disasm.o cfg.o analysis.o test_liveness.cpp
	g++ $^ $(CXXFLAGS) -o harden

test_alloc: disasm.o cfg.o analysis.o reg-alloc.o test_alloc.cpp
	g++ $^ $(CXXFLAGS) -o harden

clean:
	rm *.o harden

CXX ?= c++
CXXFLAGS ?= -O2 -g -std=c++17 -Wall -Wextra -Wpedantic
LDFLAGS ?=
COMMON := protocol.o storage.o
.PHONY: all clean test
all: cache-daemon cache-client
cache-daemon: cache-daemon.o $(COMMON)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^
cache-client: cache-client.o $(COMMON)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<
test: all
	./cache-client ping || true
clean:
	rm -f cache-daemon cache-client *.o

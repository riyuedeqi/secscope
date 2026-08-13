CXX ?= c++
CXXFLAGS ?= -O2 -g -std=c++17 -Wall -Wextra -Wpedantic
OPENSSL_CFLAGS ?= $(shell pkg-config --cflags openssl 2>/dev/null)
CPPFLAGS ?=
LDFLAGS ?=
LDLIBS ?= $(shell pkg-config --libs openssl zlib libarchive 2>/dev/null) -pthread
SOURCES := scanner.cpp file_inventory.cpp hashing.cpp resource_budget.cpp worker_pool.cpp process_snapshot.cpp socket_snapshot.cpp checkpoint.cpp native_io.cpp native_helpers.cpp runtime_snapshot.cpp file_monitor.cpp candidate_discovery.cpp filesystem_facts.cpp events_parser.cpp web_access_parser.cpp binary_analyzer.cpp static_analyzer.cpp
OBJECTS := $(SOURCES:.cpp=.o)

.PHONY: all clean test
all: scanner
scanner: $(OBJECTS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)
%.o: %.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(OPENSSL_CFLAGS) -c -o $@ $<
test: scanner
	./scanner self-test
clean:
	rm -f scanner $(OBJECTS)

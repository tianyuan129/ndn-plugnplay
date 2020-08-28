CXX = g++
CXXFLAGS = -std=c++14 -Wall `pkg-config --cflags libndn-cxx` -g
LIBS = `pkg-config --libs libndn-cxx`
DESTDIR ?= /usr/local
SOURCE_OBJS = ndn-config-client.o
PROGRAMS = ndn-config-client

all: $(PROGRAMS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -o $@ -c $< $(LIBS)

ndn-config-client: $(SOURCE_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ ndn-config-client.o $(LIBS)

clean:
	rm -f $(PROGRAMS) *.o

install: all
	cp $(PROGRAMS) $(DESTDIR)/bin/

uninstall:
	cd $(DESTDIR)/bin && rm -f $(PROGRAMS)
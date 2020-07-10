CXX = g++
CXXFLAGS = -std=c++14 -Wall `pkg-config --cflags libndn-cxx` -g
LIBS = `pkg-config --libs libndn-cxx`
DESTDIR ?= /usr/local
SOURCE_OBJS = nd-param.o nd-client.o bootstrap-client.o #nd-app.o
PROGRAMS = bootstrap-client

all: $(PROGRAMS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -o $@ -c $< $(LIBS)

bootstrap-client: $(SOURCE_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ nd-param.o nd-client.o bootstrap-client.o $(LIBS)

clean:
	rm -f $(PROGRAMS) *.o

install: all
	cp $(PROGRAMS) $(DESTDIR)/bin/

uninstall:
	cd $(DESTDIR)/bin && rm -f $(PROGRAMS)
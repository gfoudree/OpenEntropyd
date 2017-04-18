CXX = clang++
TARGET = openentropyd
CXXFLAGS = -g -std=gnu++14 -O2 -Wall -fPIE
LIBS = -lssl -lcrypto -lpthread
SOURCES = main.cpp TLSServer.cpp TLSPeer.cpp Logger.cpp EntropyPool.cpp
OBJECTS = $(SOURCES:.cpp=.o)
LD = ld

all: $(TARGET) $(SOURCES)
	@echo Done.

$(TARGET): $(OBJECTS)
	$(CXX) $(LIBS) $(OBJECTS) -o $@

.cpp.o:
	$(CXX) $(CXXFLAGS) $< -c -o $@


clean:
	rm $(TARGET)
	rm *.o

run:
	./$(TARGET)

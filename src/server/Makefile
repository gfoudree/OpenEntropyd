CXX = g++
TARGET = openentropyd
CXXFLAGS = -g -std=gnu++14 -O2 -Wall
LIBS = -lssl -lcrypto -lpthread

all:
	$(CXX) $(CXXFLAGS) -o $(TARGET)  main.cpp TLSServer.cpp TLSPeer.cpp $(LIBS)
clean:
	rm $(TARGET)
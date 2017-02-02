CXX = clang++
TARGET = openentropyd
CXXFLAGS = -g -std=gnu++14 -O2 -Wall -fPIE -pie
LIBS = -lssl -lcrypto -lpthread

all:
	$(CXX) $(CXXFLAGS) -o $(TARGET)  main.cpp TLSServer.cpp TLSPeer.cpp Logger.cpp $(LIBS)
clean:
	rm $(TARGET)
run:
	./$(TARGET)
	

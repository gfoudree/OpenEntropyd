CXX = g++
TARGET = openentropyd
CXXFLAGS = -g
LIBS = -lssl -lcrypto

all:
	$(CXX) $(CXXFLAGS) -o $(TARGET) main.cpp TLSServer.cpp $(LIBS)

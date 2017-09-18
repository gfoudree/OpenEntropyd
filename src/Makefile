CXX = clang++
TARGETS = openentropy_client openentropyd
CXXFLAGS = -g -std=gnu++14 -O0 -Wall -fPIE -I ../include
LIBS = -lssl -lcrypto -lpthread
SOURCES = $(OPENENTROPYD_SOURCES) $(OPENENTROPY_CLIENT_SOURCES)
OPENENTROPYD_SOURCES = ServerMain.cpp TLSSocket.cpp TLSServer.cpp Logger.cpp TLSPeer.cpp EntropyPool.cpp Proto.cpp
OPENENTROPYD_OBJECTS = $(OPENENTROPYD_SOURCES:.cpp=.o)
OPENENTROPY_CLIENT_SOURCES = ClientMain.cpp TLSSocket.cpp TLSClient.cpp Logger.cpp Proto.cpp
OPENENTROPYD_CLIENT_OBJECTS = $(OPENENTROPY_CLIENT_SOURCES:.cpp=.o)
LDFLAGS = $(LIBS)

all: $(SOURCES) $(TARGETS)

openentropyd: $(OPENENTROPYD_OBJECTS)
	$(CXX) $(LDFLAGS) $(OPENENTROPYD_OBJECTS) -o openentropyd
openentropy_client: $(OPENENTROPYD_CLIENT_OBJECTS)
	$(CXX) $(LDFLAGS) $(OPENENTROPYD_CLIENT_OBJECTS) -o openentropy_client
.cpp.o:
	$(CXX) $(CXXFLAGS) -c $< -o $@
.PHONY : clean
clean :
	-rm *.o
	-rm $(TARGETS)
run:
	./$(TARGET)

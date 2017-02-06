CXX = clang++
TARGET = openentropy_client
CXXFLAGS = -g -std=gnu++14 -O2 -Wall -fPIE
LIBS = -lssl -lcrypto
SOURCES = main.cpp TLSClient.cpp
OBJECTS = $(SOURCES:.cpp=.o)
LDFLAGS = $(LIBS)

all: $(SOURCES) $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(LDFLAGS) $(OBJECTS) -o $@
.cpp.o:
	$(CXX) $(CXXFLAGS) -c $< -o $@
clean:
	rm $(TARGET)
	rm *.o
run:
	./$(TARGET)
	

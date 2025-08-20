CXX := g++
CXXFLAGS := -std=c++20 -Wall -Wextra -pedantic -Wunused -Wconversion -Wsign-conversion -g -fsanitize=address
INCLUDES := -I/usr/include
LDFLAGS := -lboost_system -lboost_filesystem

TARGET := ipx
SRC := main.cpp fieldManager.cpp icmp.cpp

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $^ -o $@ $(LDFLAGS)

clean:
	rm -f $(TARGET)

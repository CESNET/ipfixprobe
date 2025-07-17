CXX := g++
CXXFLAGS := -std=c++20 -Wall -Wextra -pedantic -Wunused -Wconversion -Wsign-conversion -g -fsanitize=address
TARGET := ipx
SRC := main.cpp $(wildcard process/*/src/*.cpp)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $^ -I. -I../include/ipfixprobe/pluginFactory -o $@

clean:
	rm -f $(TARGET)

CXX := g++
CXXFLAGS := -std=c++20 -Wall -Wextra -pedantic -Wunused -Wconversion -Wsign-conversion -g -fsanitize=address
TARGET := ipx
SRC := main.cpp \
	$(wildcard process/common/*/*/*.cpp) \
	$(wildcard process/common/*/*.cpp) \
	$(wildcard process/*/src/*.cpp)

INCLUDE := -I. -I../include/ipfixprobe/pluginFactory -Iprocess/common -I../include

OBJ := $(SRC:.cpp=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) $(CXXFLAGS) $(INCLUDE) $^ -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDE) -c $< -o $@

clean:
	rm -f $(TARGET)

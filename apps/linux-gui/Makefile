# SPDX-License-Identifier: Apache-2.0
CXX      ?= g++
XFT_INC  := $(shell pkg-config --cflags xft 2>/dev/null || echo "-I/usr/include/freetype2")
XFT_LIBS := $(shell pkg-config --libs x11 xft 2>/dev/null || echo "-lX11 -lXft -lfontconfig")
CXXFLAGS ?= -std=c++20 -O3 -Wall -Wextra -Werror -I../../include $(XFT_INC)
LDFLAGS  ?= -L../../dist -lopenfir_core -Wl,-rpath,'$$ORIGIN' $(XFT_LIBS) -lm -lpthread

TARGET   := ../../dist/openfir-gui

.PHONY: all clean test

all: $(TARGET)

$(TARGET): openfir_gui.cpp ../../include/openfir.h
	@mkdir -p ../../dist
	$(CXX) $(CXXFLAGS) openfir_gui.cpp -o $(TARGET) $(LDFLAGS)

test: $(TARGET)
	$(TARGET) --smoke-test

clean:
	rm -f $(TARGET)

# SPDX-License-Identifier: Apache-2.0
CC      ?= gcc
CFLAGS  ?= -std=c11 -O3 -Wall -Wextra -Werror -I../../include
LDFLAGS ?= -L../../dist -lopenfir_core -Wl,-rpath,'$$ORIGIN' -lm -lpthread

TARGET  := ../../dist/openfir-tui

.PHONY: all clean test

all: $(TARGET)

$(TARGET): openfir_tui.c ../../include/openfir.h
	@mkdir -p ../../dist
	$(CC) $(CFLAGS) openfir_tui.c -o $(TARGET) $(LDFLAGS)

test: $(TARGET)
	$(TARGET) --smoke-test

clean:
	rm -f $(TARGET)

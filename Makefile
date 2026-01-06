# Makefile for anon_cert C implementation

# blst library path (can be overridden by environment variable)
# Default tries several common locations
BLST_DIR ?= $(shell \
	if [ -d "/tmp/blst" ]; then \
		echo "/tmp/blst"; \
	elif [ -d "/data/ljh/ljh/.cargo/registry/src/index.crates.io-6f17d22bba15001f/blst-0.3.11/blst" ]; then \
		echo "/data/ljh/ljh/.cargo/registry/src/index.crates.io-6f17d22bba15001f/blst-0.3.11/blst"; \
	else \
		echo "/tmp/blst"; \
	fi)
BLST_INCLUDE = $(BLST_DIR)/bindings
BLST_LIB = $(BLST_DIR)/libblst.a

# Compiler options
CC = gcc
CFLAGS = -Wall -Wextra -O3 -march=native -std=c11
INCLUDES = -I$(BLST_INCLUDE) -Iinclude
LIBS = $(BLST_LIB) -lm -lpthread

# Source files
SRC_DIR = src
SRCS = $(SRC_DIR)/groups.c \
       $(SRC_DIR)/accumulator.c \
       $(SRC_DIR)/zk.c \
       $(SRC_DIR)/core.c \
       $(SRC_DIR)/full_show.c \
       $(SRC_DIR)/selective_show.c

# Target files
OBJS = $(SRCS:.c=.o)
TARGET = libanon_cert.a
TEST_TARGET = test_func
PERF_TARGET = test_perf

# Default target
all: $(TARGET) check-blst-lib $(TEST_TARGET) $(PERF_TARGET)

# Static library
$(TARGET): $(OBJS)
	ar rcs $@ $^

# Compile object files
%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Test programs (require blst library)
test: check-blst-lib $(TEST_TARGET) $(PERF_TARGET)

# Check if blst library exists
check-blst-lib:
	@if [ ! -f $(BLST_LIB) ]; then \
		echo "Error: blst library not found: $(BLST_LIB)"; \
		echo ""; \
		echo "Library file $(TARGET) compiled successfully, but cannot link test programs."; \
		echo "Please do one of the following:"; \
		echo "  1. Build blst library and place it in $(BLST_DIR)/"; \
		echo "  2. Set BLST_DIR environment variable to point to directory containing libblst.a"; \
		echo "     Example: BLST_DIR=/path/to/blst make test"; \
		echo ""; \
		echo "Current blst header location: $(BLST_INCLUDE)"; \
		exit 1; \
	fi

$(TEST_TARGET): test/test_main.c $(TARGET)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(TEST_TARGET) test/test_main.c $(TARGET) $(LIBS)

$(PERF_TARGET): test/test_init_perf.c libanon_cert.a
	$(CC) $(CFLAGS) $(INCLUDES) -o $(PERF_TARGET) test/test_init_perf.c libanon_cert.a $(BLST_LIB) $(LIBS)

# Clean
clean:
	rm -f $(OBJS) $(TARGET) $(TEST_TARGET) $(PERF_TARGET)

# Check blst library
check-blst:
	@if [ ! -f $(BLST_LIB) ]; then \
		echo "Warning: blst library does not exist: $(BLST_LIB)"; \
		echo "blst header location: $(BLST_INCLUDE)"; \
		echo "Please build blst library first or set BLST_DIR environment variable to point to directory containing libblst.a"; \
		echo "Example: BLST_DIR=/path/to/blst make"; \
		exit 1; \
	fi
	@echo "Found blst library: $(BLST_LIB)"

.PHONY: all test clean check-blst check-blst-lib


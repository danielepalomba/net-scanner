CC := gcc
SRCDIR := src
BUILDDIR := build
INCDIR := $(CURDIR)/include

TARGET := app
LIBS := -lpcap

CFLAGS := -Wall -Wextra -std=gnu11 -pthread -I$(INCDIR)

DEBUG_FLAGS := -g -O0
RELEASE_FLAGS := -O2

SRCS := $(wildcard $(SRCDIR)/*.c)
OBJS := $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(SRCS))

MODE ?= release
ifeq ($(MODE),debug)
    CFLAGS += $(DEBUG_FLAGS)
else
    CFLAGS += $(RELEASE_FLAGS)
endif

.PHONY: all
all: $(BUILDDIR) $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

$(BUILDDIR)/%.o: $(SRCDIR)/%.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

.PHONY: run
run: all
	sudo ./$(TARGET)

.PHONY: clean
clean:
	rm -rf $(BUILDDIR) $(TARGET)

.PHONY: valgrind
valgrind: all
	sudo valgrind --leak-check=full ./$(TARGET)

.PHONY: debug
debug:
	$(MAKE) MODE=debug

.PHONY: release
release:
	$(MAKE) MODE=release

.PHONY: info
info:
	@echo "CC = $(CC)"
	@echo "CFLAGS = $(CFLAGS)"
	@echo "LIBS = $(LIBS)"
	@echo "MODE = $(MODE)"
	@echo "TARGET = $(TARGET)"

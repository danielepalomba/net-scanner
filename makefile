CC := gcc
SRCDIR := src
BUILDDIR := build
INCDIR := $(CURDIR)/include

ifeq ($(OS),Windows_NT)

		TARGET_NAME := app.exe
    
    NPCAP_PATH ?= ../npcap-sdk
    
    
    CFLAGS_OS := -I$(NPCAP_PATH)/Include
    LIBS := -L$(NPCAP_PATH)/Lib/x64 -lwpcap -lws2_32
     
    EXEC_CMD := ./$(TARGET)
else
   
    TARGET_NAME := app
    CFLAGS_OS := 
    LIBS := -lpcap
    EXEC_CMD := sudo ./$(TARGET)
endif

TARGET := $(TARGET_NAME)

CFLAGS := -Wall -Wextra -std=gnu11 -pthread -I$(INCDIR) $(CFLAGS_OS)

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
	$(EXEC_CMD)

.PHONY: clean
clean:
	rm -rf $(BUILDDIR) $(TARGET)

.PHONY: valgrind
valgrind: all
ifeq ($(OS),Windows_NT)
	@echo "Valgrind non e' disponibile su Windows."
else
	sudo valgrind --leak-check=full ./$(TARGET)
endif

.PHONY: debug
debug:
	$(MAKE) MODE=debug

.PHONY: release
release:
	$(MAKE) MODE=release

.PHONY: info
info:
	@echo "OS Detected = $(OS)"
	@echo "CC = $(CC)"
	@echo "CFLAGS = $(CFLAGS)"
	@echo "LIBS = $(LIBS)"
	@echo "MODE = $(MODE)"
	@echo "TARGET = $(TARGET)"

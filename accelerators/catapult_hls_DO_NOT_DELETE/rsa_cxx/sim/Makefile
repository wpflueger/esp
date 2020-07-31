# Copyright 2018 Columbia University, SLD Group

#
# Main target
#

TARGET = run

# Directories

VPATH :=
VPATH += ../tb
VPATH += ../src
VPATH += ../tb/tests

# Source files

C_SOURCES :=
C_SOURCES += rsa.cpp
C_SOURCES += main.cpp

# Include files

C_HEADERS :=
C_HEADERS += rsa.h

#
# Compiler options
#

# Compiler

CC = gcc

# Compiler flags

C_FLAGS :=
C_FLAGS += -g -ggdb
C_FLAGS += -Wall -Wextra
C_FLAGS += -Wno-unknown-pragmas
C_FLAGS += -DC_SIMULATION

# Linker flags

LD_FLAGS :=

# Linker libs

LD_LIBS :=

# Include dirs

INCDIR :=
INCDIR += -I../tb
INCDIR += -I../src

#
# Compiler rules
#

.SUFFIXES: .cpp .h .o

all: $(TARGET)

C_OBJECTS := $(C_SOURCES:.cpp=.o)

$(C_OBJECTS): $(C_HEADERS)

$(TARGET): $(C_OBJECTS)
	@echo " [LINKING]   $(TARGET)"
	@$(CC) -o $@ $(C_OBJECTS) $(LD_LIBS) $(LD_FLAGS)
	@rm -f *.o

.cpp.o:
	@echo " [COMPILING] $<"
	@$(CC)$(C_FLAGS)$(INCDIR) -c $<

clean:
	@echo " [CLEANING]"
	@rm -f *.o $(TARGET)

.PHONY: all clean check

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
VPATH += ../src/modes

# Source files

C_SOURCES :=
C_SOURCES += aes.cpp
C_SOURCES += main.cpp

# Include files

C_HEADERS :=
C_HEADERS += aes.h
C_HEADERS += dec.h
C_HEADERS += enc.h
C_HEADERS += ecb.h
C_HEADERS += cbc.h
C_HEADERS += gcm.h
C_HEADERS += defines.h

#
# Compiler options
#

# Compiler

CC = gcc

# Compiler flags

C_FLAGS :=
C_FLAGS += -g -ggdb
C_FLAGS += -Wall -Wextra
C_FLAGS += -Wno-unused-label
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
INCDIR += -I../src/modes
INCDIR += -I../utils

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

.PHONY: all clean

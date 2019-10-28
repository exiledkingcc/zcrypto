#######################################
# binaries
#######################################
# PREFIX = arm-none-eabi-
PREFIX =
# The gcc compiler bin path can be either defined in make command via GCC_PATH variable (> make GCC_PATH=xxx)
# either it can be added to the PATH environment variable.
ifdef GCC_PATH
CC = $(GCC_PATH)/$(PREFIX)gcc
AS = $(GCC_PATH)/$(PREFIX)gcc -x assembler-with-cpp
CP = $(GCC_PATH)/$(PREFIX)objcopy
SZ = $(GCC_PATH)/$(PREFIX)size
else
CC = $(PREFIX)gcc
AS = $(PREFIX)gcc -x assembler-with-cpp
CP = $(PREFIX)objcopy
SZ = $(PREFIX)size
endif
HEX = $(CP) -O ihex
BIN = $(CP) -O binary -S

CFLAGS = -g -Wall -std=c11

LIBS = -lc -lm
LIBDIR =
LDFLAGS = $(LIBDIR) $(LIBS)


BUILD_DIR = build

SOURCES = \
test.c \
zcrypto/cipher.c \
zcrypto/aes.c \
zcrypto/md5.c \
zcrypto/sha1.c \
zcrypto/sha256.c \
zcrypto/sm3.c \
zcrypto/sm4.c

OBJECTS = $(addprefix $(BUILD_DIR)/,$(notdir $(SOURCES:.c=.o)))
vpath %.c $(sort $(dir $(SOURCES)))

all: $(BUILD_DIR)/test.elf

$(BUILD_DIR)/%.elf: $(OBJECTS) Makefile
	$(CC) $(OBJECTS) $(LDFLAGS) -o $@
	$(SZ) $@

$(BUILD_DIR)/%.o: %.c Makefile | $(BUILD_DIR)
	$(CC) -c $(CFLAGS) -Wa,-a,-ad,-alms=$(BUILD_DIR)/$(notdir $(<:.c=.lst)) $< -o $@

$(BUILD_DIR):
	mkdir $@


.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)

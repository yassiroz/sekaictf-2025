CC = gcc
CFLAGS = -Wall -Wextra -Wl,-z,relro -no-pie -fno-stack-protector
LDFLAGS= -lfuse3 -lvulkan -lssl -lcrypto
SRC = src/vkfs.c
OBJ = src/vkfs.o
BIN = vkfs

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $(BIN) $(OBJ) $(LDFLAGS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(BIN)

CC = clang
CFLAGS = -I./include -Wall -Wextra -std=c99 -g
SDK_PATH = /usr/share/SDKs/iPhoneOS.sdk
LDFLAGS = -lcapstone
SRC_DIR = src
OBJ_DIR = obj
SRC = $(wildcard $(SRC_DIR)/*.c)
OBJ = $(SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
TARGET = macho-dumper

$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

ios:
	$(CC) -isysroot $(SDK_PATH) -arch arm64 -I./include $(SRC) -lcapstone -o $(TARGET)_ios

simulator:
	$(CC) -isysroot $(SDK_PATH) -arch x86_64 -I./include $(SRC) -lcapstone -o $(TARGET)_sim

clean:
	rm -rf $(OBJ_DIR) $(TARGET) $(TARGET)_ios $(TARGET)_sim

.PHONY: clean ios simulator

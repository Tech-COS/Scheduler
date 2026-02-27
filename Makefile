########################
##
##  Created: Sun Nov 03 2024
##  File: Makefile
##
########################

SRC_PATH = src
BUILD_PATH = build
BUILD_PATH_API = build
COMPILER = gcc
FILE_TYPE = .c

TEST_COMPILER = gcc
TEST_LINKER = ld
TESTING ?= 0

ifeq (${TESTING}, 1)
	KERNEL_COMPILER = ${TEST_COMPILER}
	LINKER = ${TEST_LINKER}
endif

SRC_MAIN =\
	${SRC_PATH}/main.c\

SRC =	${SRC_PATH}/scheduling_init.c\
		${SRC_PATH}/scheduling_memory_handling.c\
		${SRC_PATH}/scheduling_functions.c\

INCLUDE =\
	-I./include/\
	-I../include/\

BUILD_DIR = ./build
OBJ = ${SRC:${SRC_PATH}/%${FILE_TYPE}=${BUILD_PATH}/%.o}
OBJ_MAIN = ${SRC_MAIN:${SRC_PATH}/%${FILE_TYPE}=${BUILD_PATH}/%.o}
OBJ_FLAGS = -W -Wall -Wextra -Werror ${INCLUDE} -m64 -mcmodel=large -mlarge-data-threshold=2147483647 -ffreestanding -mno-red-zone -nostdlib -g3 -Wall -Wextra -z noexecstack -z max-page-size=0x1000 -fPIC
BIN_FLAGS =
BIN_NAME = scheduler
LIB_NAME = libscheduler.a
TEST_NAME = test_run

# Testing properties
SRC_TEST_TYPE = .c
SRC_TEST_DIR = ./test/src
SRC_TEST =	${SRC_TEST_DIR}/unity.c\
			${SRC_TEST_DIR}/test_utilities.c\
			${SRC_TEST_DIR}/test_exposed_functions.c\

HEADER_TEST =\
	-I./test/include/\
	${HEADERS_KERNEL}\

BUILD_TEST_PATH = ${BUILD_DIR}/test
OBJ_TEST = ${SRC_TEST:${SRC_TEST_DIR}/%${SRC_TEST_TYPE}=${BUILD_TEST_PATH}/%.o}
TEST_FLAGS = -g3 -Wall -Wextra -Werror -MD ${HEADER_TEST} ${INCLUDE}

all: ${BIN_NAME}
lib: ${LIB_NAME}

debug: OBJ_FLAGS += -DDEBUG -g3

${BUILD_PATH}/%.o: ${SRC_PATH}/%${FILE_TYPE}
	mkdir -p ${dir $@}
	${COMPILER} -DCOS_COMPILATION=1 -MD ${OBJ_FLAGS} -c $< -o $@

${BIN_NAME}: ${OBJ} ${OBJ_MAIN}
	${COMPILER} -o ${BIN_NAME} ${OBJ} ${OBJ_MAIN} ${BIN_FLAGS}

${LIB_NAME}: ${OBJ}
	ar rcs ${LIB_NAME} ${OBJ}

${LIB_NAME_API}: ${OBJ_API}
	ar rcs ${LIB_NAME_API} ${OBJ_API}

${BUILD_TEST_PATH}/%.o: ${SRC_TEST_DIR}/%${SRC_TEST_TYPE}
	@mkdir -p ${dir $@}
	${TEST_COMPILER} -c $< -o $@ ${TEST_FLAGS}

${TEST_NAME}: ${OBJ_TEST} ${OBJ} ${LIB_NAME}
	ar rcs ${LIB_NAME} ${OBJ}
	${TEST_COMPILER} -o ${TEST_NAME} ${OBJ_TEST} ${LIB_NAME}

clean:
	rm -rf ${BUILD_PATH}

fclean: clean
	rm -rf ${LIB_NAME_API}
	rm -rf ${LIB_NAME}
	rm -rf ${BIN_NAME}

-include ${OBJ:%.o=%.d}

.PHONY: all clean fclean

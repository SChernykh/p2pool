CC=gcc
CFLAGS=-Wall --std=c99 
SRC=siphash.c halfsiphash.c test.c testmain.c
HEADERS=siphash.h halfsiphash.h
BIN=test debug vectors

ifneq ($(cROUNDS),)
CFLAGS:=$(CFLAGS) -DcROUNDS=$(cROUNDS)
endif

ifneq ($(dROUNDS),)
CFLAGS:=$(CFLAGS) -DdROUNDS=$(dROUNDS)
endif

.PHONY: analyze sanitize lint format clean  


all:                    $(BIN)

everything:             clean format lint analyze sanitize test vectors

test:                   $(SRC)
			$(CC) $(CFLAGS) $^ -o $@ 

debug:                  $(SRC) 
			$(CC) $(CFLAGS) -g $^ -o $@ -DDEBUG_SIPHASH

vectors:                $(SRC) 
			$(CC) $(CFLAGS) $^ -o $@ -DGETVECTORS

analyze:                $(SRC)
			scan-build $(CC) $(CFLAGS) $^ -o $@
			rm -f $@

sanitize:               $(SRC)
			$(CC) -fsanitize=address,undefined $(CFLAGS) $^ -o $@
			./$@
			rm -f $@

lint:                   $(SRC) $(HEADERS) 
			cppcheck --std=c99 $^
format:
		        clang-format -style="{BasedOnStyle: llvm, IndentWidth: 4}" \
			-i *.c *.h 
clean:
			rm -f *.o $(BIN) analyze sanitize



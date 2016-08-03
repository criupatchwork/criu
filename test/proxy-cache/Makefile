DIR	:= $(shell pwd)/data
CRIU	:= $(DIR)/criu

LOOP	:= $(DIR)/loop.sh
PIDFILE := $(DIR)/loop.pid

DUMPDIR	:= $(DIR)/dump
PREDIR	:= $(DIR)/predump
LOG	:= $(DIR)/log

PROXY_CACHE_TCP_PORT	:= 9997
LOCAL_CACHE_PATH	:= $(DIR)/image-cache.sock
LOCAL_PROXY_PATH	:= $(DIR)/image-proxy.sock

export DIR LOOP PIDFILE DUMPDIR PREDIR CRIU LOG PROXY_CACHE_TCP_PORT LOCAL_CACHE_PATH LOCAL_PROXY_PATH

run: testdir
	./run.sh

testdir: ../../criu
	mkdir -p $(DIR)
	mkdir -p $(DUMPDIR)
	mkdir -p $(PREDIR)
	mkdir -p $(LOG)
	cp ../../criu/criu $(CRIU)
	cp loop.sh $(LOOP)

clean:
	rm -rf $(DIR)

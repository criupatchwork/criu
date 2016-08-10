#!/bin/bash

set -x

PID=
CACHE_PID=
PROXY_PID=

function run {
	echo "== Run ${LOOP}"
	echo ${PIDFILE}
	rm -f ${PIDFILE}
	setsid ${LOOP} ${PIDFILE} < /dev/null &> /dev/null &
	for i in `seq 100`; do
		test -f ${PIDFILE} && break
		sleep 1
	done
	PID=`cat ${PIDFILE}`
	echo ${PID}
}

function prepare {
        ${CRIU} image-cache -vvvv -o ${LOG}/image-cache.log \
						--local-cache-path ${LOCAL_CACHE_PATH} \
						--port ${PROXY_CACHE_TCP_PORT} < /dev/null &> /dev/null &
        CACHE_PID=$!
        sleep 1

        ${CRIU} image-proxy -vvvv -o ${LOG}/image-proxy.log \
						--local-proxy-path ${LOCAL_PROXY_PATH} \
						--address localhost \
						--port ${PROXY_CACHE_TCP_PORT} < /dev/null &> /dev/null &
        PROXY_PID=$!
        sleep 1
}

function predump {
	test -d ${PREDIR} && rm -rf ${PREDIR}
	mkdir -p ${PREDIR}
	echo "== Predump ${PID}"
	${CRIU} pre-dump -vvvv --tree ${PID} --images-dir ${PREDIR} \
					 -o ${LOG}/predump.log \
					 --remote --local-proxy-path ${LOCAL_PROXY_PATH}
	return $?
}

function dump {
	test -d ${DUMPDIR} && rm -rf ${DUMPDIR}
	mkdir -p ${DUMPDIR}
	echo "== Dump ${PID}"
	${CRIU} dump -vvvv --tree ${PID} --images-dir ${DUMPDIR} \
			-o ${LOG}/dump.log --prev-images-dir ${PREDIR} --track-mem \
			--remote --local-proxy-path ${LOCAL_PROXY_PATH}
	return $?
}

function restore {
	echo "== Restore ${DUMPDIR}"
	${CRIU} restore -vvvv --images-dir ${DUMPDIR} --restore-detached \
			-o ${LOG}/restore.log \
			--remote --local-cache-path ${LOCAL_CACHE_PATH}
	return $?
}

function result {
	local BGRED='\033[41m'
	local BGGREEN='\033[42m'
	local NORMAL=$(tput sgr0)

	if [ $1 -ne 0 ]; then
		echo -e "${BGRED}FAIL${NORMAL}"
		exit 1
	else
		echo -e "${BGGREEN}PASS${NORMAL}"
	fi
}

function test_dump_restore {
	echo "==== Check if dump-restore works with proxy-cache"

	run
	prepare
	dump; result $(($?))
	restore ; result $(($?))

	kill -SIGKILL ${PID}
    kill -SIGKILL ${CACHE_PID}
    kill -SIGKILL ${PROXY_PID}
}

function test_predump_dump_restore {
	echo "==== Check if predump-dump-restore works with proxy-cache"

	run
	prepare
	predump; result $(($?))
	dump; result $(($?))
	restore ; result $(($?))

	kill -SIGKILL ${PID}
	kill -SIGKILL ${CACHE_PID}
	kill -SIGKILL ${PROXY_PID}
}

test_dump_restore
test_predump_dump_restore

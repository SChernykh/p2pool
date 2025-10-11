#!/bin/bash
grep 'ERROR ' p2pool.log | grep -E -v 'submit_block|failed to bind|ZMQ is not running' > errors.log

if [ -s errors.log ]; then
	cat errors.log
	exit 1
fi

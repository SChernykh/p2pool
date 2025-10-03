#!/bin/bash
grep 'ERROR ' p2pool.log | grep -E -v 'submit_block|failed to bind' > errors.log

if [ -s errors.log ]; then
	exit 1
fi

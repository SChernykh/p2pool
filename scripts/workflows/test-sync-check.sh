#!/bin/bash
grep 'ERROR ' p2pool.log | grep -E -v 'submit_block|failed to bind|ZMQ is not running|block header for seed|ZMQReader|ZMQ reader|uv_poll_start returned error EBADF|Sidechain block has wrong PoW' > errors.log

if [ -s errors.log ]; then
	cat errors.log
	exit 1
fi

if ! grep 'submit_sidechain_block: template id =' p2pool_stdout.log; then
	echo "p2pool::submit_sidechain_block didn't execute"
	exit 1
fi

if ! grep 'received a longer alternative chain: height' p2pool_stdout.log; then
	echo "sidechain switch didn't happen"
	exit 1
fi

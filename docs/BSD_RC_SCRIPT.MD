## Setting up P2Pool as a service controlled by a RC script (FreeBSD, and possibly other)

In order to use this RC script, it is required to create a `p2pool` user account on the system for this service. An example **passwd(5)** line for this user would be:
```
p2pool:*:818:818::0:0:Monero P2Pool:/var/db/p2pool:/usr/sbin/nologin
```
Also an example **group(5)** line:
```
p2pool:*:818:
```

When creating such an user and a group, make sure the UID and GID aren't being used by any other user/group in the system. The home directory of the user will be used as the data directory of P2Pool; set it to your desired location as needed.

The RC script assumes the P2Pool executable is installed as `/usr/local/bin/p2pool`.

### /usr/local/etc/rc.d/p2pool
```sh
#!/bin/sh

# PROVIDE: p2pool
# REQUIRE: LOGIN FILESYSTEMS
# KEYWORD: shutdown

. /etc/rc.subr

name=p2pool
rcvar=p2pool_enable

load_rc_config $name

: ${p2pool_enable:="NO"} ${p2pool_local_api:="NO"}

[ -z "$p2pool_wallet" ] && exit 1
p2pool_user=p2pool
p2pool_home="`getent passwd ${p2pool_user} | cut -d : -f 6`"
[ -z "$p2pool_home" ] && exit 1
p2pool_env="HOME=$p2pool_home"
p2pool_chdir="$p2pool_home"
procname=/usr/local/bin/p2pool
pidfile="$p2pool_home/p2pool.pid"
command=/usr/sbin/daemon
flags="-p ${pidfile} -f -- ${procname} ${p2pool_flags} --data-dir ${p2pool_home} --wallet ${p2pool_wallet}"
[ -n "${p2pool_api_path}" ] && flags="${flags} --data-api ${p2pool_api_path}"
if checkyesno p2pool_local_api; then
	if [ -n "${p2pool_api_path}" ]; then
		flags="${flags} --local-api"
	else
		echo 'Warning: p2pool_local_api="YES" requires p2pool_api_path being set, ignoring' 1>&2
	fi
fi
start_precmd="p2pool_prestart"
stop_postcmd="rm -f ${pidfile}"

p2pool_prestart() {
	if [ -n "${p2pool_api_path}" ]; then
		[ -d "${p2pool_api_path}" ] || mkdir -p "${p2pool_api_path}"
		gid="`getent passwd ${p2pool_user} | cut -d : -f 4`"
		chown ${p2pool_user}:${gid} "${p2pool_api_path}"
	fi
}

run_rc_command "$1"
```

### Configuration variables in /etc/rc.conf (or /etc/rc.conf.local)

* `p2pool_enable` Set to `YES` to enable this service; required.
* `p2pool_wallet` Your wallet address; required.
* `p2pool_api_path` Path to API directory (See p2pool option `--data-api`), this directory will be created automatically if not already exists, on service startup; optional.
* `p2pool_local_api` Set to `YES` to enable creation of `local` path in API directory (See p2pool option `--local-api`), requires `p2pool_api_path` also being set; optional.
* `p2pool_flags` Additional options you want to pass to p2pool; optional.

#### Example
```sh
p2pool_enable="YES"
p2pool_wallet="44MnN1f3Eto8DZYUWuE5XZNUtE3vcRzt2j6PzqWpPau34e6Cf4fAxt6X2MBmrm6F9YMEiMNjN6W4Shn4pLcfNAja621jwyg"
p2pool_api_path="/tmp/p2pool-api"
p2pool_local_api="YES"
p2pool_flags="--host 127.0.0.1 --in-peers 200"
```

## /usr/local/etc/newsyslog.conf.d/p2pool.conf (optional)

You can create this drop-in **newsyslog(8)** configuration file to periodically rotate the P2Pool log file. The drop-in location `/usr/local/etc/newsyslog.conf.d/` assumes that `/etc/newsyslog.conf` contains an `include` directive for searching drop-in configuration files in it.

This example assumes `/var/db/p2pool` as your P2Pool data directory.

```
# log file			owner:group		mode	count	size (KiB)	when	flags	pid file				signal
/var/db/p2pool/p2pool.log	p2pool:p2pool		640	16	65536		@0101T	BEJ	/var/db/p2pool/p2pool.pid		SIGUSR1
```

You should adjust the `count`, `size`, `when` and/or `flags` fields to fit your needs.

#!/usr/bin/env python3
import json
from datetime import datetime
from prefixed import Float
import humanfriendly
from flask import Flask, render_template

app = Flask(__name__)


##
# Add some custom jinja filters
def timeago(value):
    """Format a date time to human friendly time ago"""
    if value is None:
        return ""
    if type(value) is int:
        dt = datetime.fromtimestamp(value).replace(microsecond=0)
    now = datetime.now().replace(microsecond=0)
    return humanfriendly.format_timespan(now - dt)


app.jinja_env.filters["timeago"] = timeago


def human_numbers(value):
    """Format a number in human readable format"""
    if value is None:
        return ""
    return "{:!.3h}".format(Float(value))


app.jinja_env.filters["humanize"] = human_numbers


##
# Get Pool Instance Birth Date
def birthdate():
    try:
        with open("/data/p2pool.blocks") as reader:
            first_block = reader.readline().rstrip()
        bday_ts = int(first_block.split(" ")[0])
        bday = timeago(bday_ts)
        return bday
    except Exception as e:
        return "unknown time"


##
# The App Routes
@app.route("/")
def render():
    try:
        my_bday = birthdate()
        with open("/data/stats_mod", "r") as reader:
            stats_mod = json.loads(reader.read())
        with open("/data/pool/stats", "r") as reader:
            pool_stats = json.loads(reader.read())
        with open("/data/network/stats", "r") as reader:
            network_stats = json.loads(reader.read())
        with open("/data/local/stratum", "r") as reader:
            local_stats = json.loads(reader.read())
        workers = local_stats["workers"][:30] # limit workers output list
        workers_concat = []
        for w in workers:
            w_list = w.split(",")
            w_list[1] = humanfriendly.format_timespan(int(w_list[1]))
            w_list[2] = human_numbers(int(w_list[2]))
            w_list[3] = human_numbers(int(w_list[3]))
            workers_concat.append(w_list)
        return render_template(
            "index.html",
            my_bday=my_bday,
            stats_mod=stats_mod,
            pool_stats=pool_stats,
            network_stats=network_stats,
            local_stats=local_stats,
            workers=workers_concat,
        )
    except Exception as e:
        return render_template("oops.html", error=str(e))


##
# main()
if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=80)

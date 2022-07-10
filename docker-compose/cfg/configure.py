#!/bin/env python3
import sys
import time
import json
from jinja2 import Template
import npyscreen

# Help text in a box at the bottom of the screen
class HelpBoxBase(npyscreen.BoxTitle):
    def splitlines(self):
        all_help = []
        for fld, msg in self.help_msgs.items():
            if fld[-1] != ":":
                fld += ":"
            message = [m.lstrip() for m in msg if m != ""]
            helpline = f"{fld:<28}{'. '.join(message)}"
            all_help.append(helpline)
            all_help.append("")
        return all_help

    def display_help_message(self, field):
        self.set_values(
            self.help_msgs.get(field, "No help availabe for {}".format(field))
        )
        self.clear()
        self.display()


class P2PoolHelpBox(HelpBoxBase):
    help_msgs = {
        "Wallet Address:": [
            "Your monero wallet address for receiving mining reqards",
            "",
            "Note: You have to use a primary wallet address for mining",
            "      Subaddresses and integrated addresses are not supported!",
        ],
        "P2Pool Sidechain:": [
            "Which P2Pool sidechain to mine on",
            "    use main for faster miners",
            "    use mini for slower miners",
        ],
        "Enable Server Statistics": [
            "Provide access to your P2Pool server statictics via a web interface",
        ],
        "Statistics Port:": [
            "Port number (or IP:Port) to expose web access to your P2Pool server",
            "statictics",
        ],
        "Expose Stratum Port": [
            "Expose the P2Pool stratum port to your network so external miners",
            "can connect",
            "Note: You may choose to open this port in your hosts firewall and/or",
            "      router to allow miners outside your network to connect",
        ],
        "Stratum Port:": [
            "Port number (or IP:Port) to expose P2Pool stratum to your network to",
            "allow external miners to connect",
            "Note: You may choose to open this port in your hosts firewall and/or",
            "      router to allow miners outside your network to connect",
        ],
        "P2Pool Log Level:": [
            "Verbosity of the log; (Less) 0 - 6 (More)",
        ],
        "Enable Autodiff": [
            "Use automatic difficulty adjustment for miners connected to stratum",
        ],
        "Enable Light Mode": [
            "Don't allocate RandomX dataset, saves 2GB of RAM",
        ],
        "Disable Cache": [
            "Disable p2pool.cache (not recommended)",
        ],
        "Additional P2Pool Options:": [
            "Additional options to pass to p2pool commandline",
            "",
            "Note: Advanced - Only add options if you know what you are doing",
            "      See ouput of 'p2pool --help' for available options",
        ],
        "Next": [
            "Next configuration menu",
        ],
        "Save": [
            "Save current configuration and exit",
        ],
        "Cancel": [
            "Exit without saving",
        ],
    }


class MoneroHelpBox(HelpBoxBase):
    help_msgs = {
        "Configure Monero Node": [
            "Configure and run a Monero Node",
            "",
            "Note: You must either configure a local node or specify a public node",
        ],
        "Monero Version:": [
            "Version of Monero to build; 'latest' for the most recent release",
            "",
            "Note: Must be v0.17.3.0 or later for p2pool support",
            "      See: https://github.com/monero-project/monero/tags",
        ],
        "Prune Blockchain": [
            "Prune the Monero node to limit the size of the blockchain on disk",
        ],
        "Monero Log Level:": [
            "Verbosity of the log; (Less) 0 - 4 (More)",
            "",
            "Note: settings above 0 are very noisy",
        ],
        "Expose RPC Port": [
            "Expose restricted RPC API port to your network so external services",
            "(wallets for example) can connect",
            "Note: You may choose to open this port in your hosts firewall and/or",
            "      router to allow services outside your network to connect",
        ],
        "RPC Port:": [
            "TCP port to listen on for RPC connections",
        ],
        "RPC Login:": [
            "Specify username[:password] required to connect to the RPC API",
        ],
        "Limit Data Rates": [
            "Set a limit value for incoming and outgoing data transfer",
        ],
        "Rate Limit Up:": [
            "Set outgoing data transfer limit [kB/s]",
        ],
        "Rate Limit Down:": [
            "Set incoming data transfer limit [kB/s]",
        ],
        "Sync Pruned Blocks": [
            "Accept pruned blocks instead of pruning yourself to save",
            "network transfer",
        ],
        "Fast Block Sync": [
            'Sync up most of the way by using embedded, "known" (old) block',
            "hashes without calculating the block hash to verify the proof of work",
            "",
            "Note: Faster initial sync by trusting the monerod binary",
        ],
        "Public Node:": [
            "Public Monero Node to Use",
            "",
            "Note: The public node must have both Monero RPC and zmq-pub ports",
            "      available",
        ],
        "Node Login:": [
            "Specify username[:password] required to connect to public monero",
            "node RPC API (if required)",
        ],
        "Additional monerod Options:": [
            "Additional options to pass to monerod commandline",
            "",
            "Note: Advanced - Only add options if you know what you are doing",
            "      See 'https://monerodocs.org/interacting/monerod-reference/'",
        ],
        "Prev": [
            "Previous configuration menu",
        ],
        "Next": [
            "Next configuration menu",
        ],
        "Save": [
            "Save current configuration and exit",
        ],
        "Cancel": [
            "Exit without saving",
        ],
    }


class XMRigHelpBox(HelpBoxBase):
    help_msgs = {
        "Configure XMRig CPU Miner": [
            "Configure and run an XMRig CPU Miner",
            "",
            "Note: You must either configure am XMRig CPU Miner or expose the",
            "      P2Pool stratum port and connect an external miner, or both",
        ],
        "Username:": [
            "Set a username for the miner",
        ],
        "Use Fixed Difficulty": [
            "Used a fixed minig difficulty",
            "",
            "Note: Allows you to see XMRig submitting shares below P2Pool threshold",
        ],
        "Fixed Difficulty:": [
            "Set a fixed mining difficulty",
            "",
            "Note: Allows you to see XMRig submitting shares below P2Pool threshold",
        ],
        "CPU Use %:": [
            "Maximum CPU threads count (in percentage) hint for autoconfig",
            "Note: Applies to cores only.  If you have HyperThreading enabled you",
            "      should divide this value by 2 (use 0-50%).  Reference:",
            "      https://github.com/xmrig/xmrig/issues/1670#issuecomment-644433778",
        ],
        "CPU Priority:": [
            "Set process priority (0 idle, 2 normal to 5 highest)",
        ],
        "Additional XMRig Options:": [
            "Additional options to pass to xmrig",
            "",
            "Note: Advanced - Only add options if you know what you are doing",
            "      See 'https://xmrig.com/docs/miner/command-line-options'",
        ],
        "Prev": [
            "Previous configuration menu",
        ],
        "Save": [
            "Save current configuration and exit",
        ],
        "Cancel": [
            "Exit without saving",
        ],
    }


##
# Custom (integer) values for title slider
class IntegerSlider(npyscreen.Slider):
    def translate_value(self):
        from_val = int(str(self.value).split(".")[0])
        out_of_val = int(str(self.out_of).split(".")[0])
        if from_val >= 1000:
            from_val = str(from_val / 1000).split(".")[0] + "K"
            out_of_val = str(out_of_val / 1000).split(".")[0] + "K"
        return "{}/{}".format(from_val, out_of_val)


class TitleIntegerSlider(npyscreen.TitleSlider):
    _entry_type = IntegerSlider


##
# Patched updateDependents for FormControlCheckbox
class PatchedFormControlCheckbox(npyscreen.FormControlCheckbox):
    def updateDependents(self):
        if self.value:
            for w in self._visibleWhenSelected:
                try:
                    w.fc_visible
                except AttributeError:
                    w.fc_visible = {}
                w.fc_visible[self.name] = True
            for w in self._notVisibleWhenSelected:
                try:
                    w.fc_visible
                except AttributeError:
                    w.fc_visible = {}
                w.fc_visible[self.name] = False
        else:
            for w in self._visibleWhenSelected:
                try:
                    w.fc_visible
                except AttributeError:
                    w.fc_visible = {}
                w.fc_visible[self.name] = False
            for w in self._notVisibleWhenSelected:
                try:
                    w.fc_visible
                except AttributeError:
                    w.fc_visible = {}
                w.fc_visible[self.name] = True
        for w in self._visibleWhenSelected + self._notVisibleWhenSelected:
            w.hidden = False in w.fc_visible.values()
            w.editable = not False in w.fc_visible.values()
        self.parent.display()

    def set_value(self, value):
        self.value = value
        self.display()

    def display(self):
        self.updateDependents()
        super()


class PrevButton(npyscreen.Button):
    def whenToggled(self):
        self.value = False
        self.parent.prev_form()


class NextButton(npyscreen.Button):
    def whenToggled(self):
        self.value = False
        self.parent.next_form()


class SaveButton(npyscreen.Button):
    def whenToggled(self):
        self.find_parent_app().save_and_exit()


class CancelButton(npyscreen.Button):
    def whenToggled(self):
        self.find_parent_app().cancel_and_exit()


##
# Config Forms Base Class
class ConfigFormBase(npyscreen.FormBaseNew):
    name_size = 20
    indent = 5
    current_config = None
    defaults = None
    ALLOW_RESIZE = False

    def while_editing(self, arg):
        self.help.display_help_message(arg.name)
        self.display()

    def get_default_config(self):
        # Return defaults
        if self.defaults is None:
            with open("defaults") as defaults_file:
                self.defaults = json.load(defaults_file)
        return self.defaults

    def get_current_config(self):
        # Return current config
        if self.current_config is None:
            # Read current config
            with open("/docker-compose/current_config") as current_config:
                self.current_config = json.load(current_config)
        return self.current_config

    def reset_defaults(self, arg):
        # Set config to default values
        ok = npyscreen.notify_ok_cancel(
            "Set current form values to defaults", title="Reset to Defaults"
        )
        if not ok:
            return
        defaults = self.get_default_config()
        self.set_config(defaults)


##
# P2Pool Configuration Form
class P2PoolConfigForm(ConfigFormBase):
    def create(self):
        # Add Hot-Key Controls
        self.add_handlers({"^D": self.reset_defaults})
        # Add P2Pool Configuration
        self.add(
            npyscreen.TitleText,
            name="## P2Pool Configuration",
            editable=False,
            begin_entry_at=50,
        )
        self.wallet_address = self.add(
            npyscreen.TitleText,
            name="Wallet Address:",
            value="",
            begin_entry_at=self.name_size,
            relx=self.indent,
        )
        self.nextrely += 1
        self.sidechain = self.add(
            npyscreen.TitleSelectOne,
            name="P2Pool Sidechain:",
            values=["main", "mini"],
            scroll_exit=True,
            max_height=2,
            value=[
                0,
            ],
            begin_entry_at=self.name_size,
            relx=self.indent,
        )
        self.nextrely += 1
        self.enable_statistics = self.add(
            PatchedFormControlCheckbox,
            name="Enable Server Statistics",
            value=True,
            begin_entry_at=self.name_size,
            relx=self.indent,
        )
        self.statistics_port = self.add(
            npyscreen.TitleText,
            name="Statistics Port:",
            value="3334",
            begin_entry_at=self.name_size,
            relx=self.indent,
        )
        self.enable_statistics.addVisibleWhenSelected(self.statistics_port)
        self.nextrely += 1
        self.expose_stratum_port = self.add(
            PatchedFormControlCheckbox,
            name="Expose Stratum Port",
            value=True,
            begin_entry_at=self.name_size,
            relx=self.indent,
        )
        self.stratum_port = self.add(
            npyscreen.TitleText,
            name="Stratum Port:",
            value="3333",
            begin_entry_at=self.name_size,
            relx=self.indent,
        )
        self.expose_stratum_port.addVisibleWhenSelected(self.stratum_port)
        self.nextrely += 1
        self.p2pool_log_level = self.add(
            TitleIntegerSlider,
            name="P2Pool Log Level:",
            out_of=6,
            value=3,
            lowest=0,
            step=1,
            width=43,
            begin_entry_at=20,
            label=True,
            block_color=None,
            relx=self.indent,
        )
        self.nextrely += 1
        self.autodiff = self.add(
            PatchedFormControlCheckbox,
            name="Enable Autodiff",
            value=True,
            begin_entry_at=self.name_size,
            relx=self.indent,
        )
        self.nextrely += 1
        self.light_mode = self.add(
            PatchedFormControlCheckbox,
            name="Enable Light Mode",
            value=False,
            begin_entry_at=self.name_size,
            relx=self.indent,
        )
        self.nextrely += 1
        self.no_cache = self.add(
            npyscreen.Checkbox,
            name="Disable Cache",
            value=False,
            begin_entry_at=self.name_size,
            relx=self.indent,
        )
        self.nextrely += 1
        self.p2pool_extra = self.add(
            npyscreen.TitleText,
            name="Additional P2Pool Options:",
            value="",
            begin_entry_at=self.name_size + 10,
            relx=self.indent,
        )
        self.nextrely += 1
        self.nextrely += 1
        # Add "Next", "Save", and "Cancel" buttons
        self.next_button = self.add(NextButton, name="Next", relx=1)
        self.nextrely -= 1
        self.save_button = self.add(SaveButton, name="Save", relx=8)
        self.nextrely -= 1
        self.cancel_button = self.add(CancelButton, name="Cancel", relx=15)
        self.nextrely += 1
        # Add Help Box
        self.help = self.add(
            P2PoolHelpBox,
            name="Commands:  ^D: Load Defaults  -  ^C: Exit Without Saving",
            values=[""],
            editable=False,
        )
        # Start with current config
        self.set_config(self.get_current_config())

    def next_form(self):
        self.find_parent_app().switchForm("MONERO")

    def set_config(self, config):
        self.wallet_address.set_value(config["wallet_address"])
        self.sidechain.set_value(config["sidechain"])
        self.enable_statistics.set_value(config["enable_statistics"])
        self.statistics_port.set_value(config["statistics_port"])
        self.expose_stratum_port.set_value(config["expose_stratum_port"])
        self.stratum_port.set_value(config["stratum_port"])
        self.p2pool_log_level.set_value(config["p2pool_log_level"])
        self.autodiff.set_value(config["enable_autodiff"])
        self.light_mode.set_value(config["light_mode"])
        self.no_cache.value = config["no_cache"]
        self.p2pool_extra.set_value(config["p2pool_options"])
        self.DISPLAY()

    def get_config(self):
        config = {
            "wallet_address": self.wallet_address.value,
            "sidechain": self.sidechain.value,
            "enable_statistics": self.enable_statistics.value,
            "statistics_port": self.statistics_port.value,
            "expose_stratum_port": self.expose_stratum_port.value,
            "stratum_port": self.stratum_port.value,
            "p2pool_log_level": self.p2pool_log_level.value,
            "enable_autodiff": self.autodiff.value,
            "light_mode": self.light_mode.value,
            "no_cache": self.no_cache.value,
            "p2pool_options": self.p2pool_extra.value,
        }
        return config


##
# Monero Configuration Form
class MoneroConfigForm(ConfigFormBase):
    def create(self):
        # Add Hot-Key Controls
        self.add_handlers({"^D": self.reset_defaults})
        # Add Monero Configuration
        self.add(
            npyscreen.TitleText,
            name="## Monero Node Configuration",
            editable=False,
            begin_entry_at=50,
        )
        self.configure_monero_node = self.add(
            PatchedFormControlCheckbox,
            name="Configure Monero Node",
            value=True,
            relx=self.indent,
        )
        self.nextrely += 1
        self.monero_git_tag = self.add(
            npyscreen.TitleText,
            name="Monero Version:",
            value="latest",
            begin_entry_at=self.name_size,
            relx=self.indent,
        )
        self.configure_monero_node.addVisibleWhenSelected(self.monero_git_tag)
        self.prune_node = self.add(
            PatchedFormControlCheckbox,
            name="Prune Blockchain",
            value=True,
            begin_entry_at=self.name_size,
            relx=self.indent,
        )
        self.configure_monero_node.addVisibleWhenSelected(self.prune_node)
        self.monero_log_level = self.add(
            TitleIntegerSlider,
            name="Monero Log Level:",
            out_of=4,
            value=0,
            lowest=0,
            step=1,
            width=43,
            begin_entry_at=20,
            label=True,
            block_color=None,
            relx=self.indent,
        )
        self.configure_monero_node.addVisibleWhenSelected(self.monero_log_level)
        self.nextrely += 1
        self.expose_rpc_port = self.add(
            PatchedFormControlCheckbox,
            name="Expose RPC Port",
            value=False,
            relx=self.indent,
        )
        self.configure_monero_node.addVisibleWhenSelected(self.expose_rpc_port)
        self.rpc_port = self.add(
            npyscreen.TitleText,
            name="RPC Port:",
            value="18081",
            begin_entry_at=self.name_size,
            relx=self.indent,
        )
        self.configure_monero_node.addVisibleWhenSelected(self.rpc_port)
        self.expose_rpc_port.addVisibleWhenSelected(self.rpc_port)
        self.rpc_login = self.add(
            npyscreen.TitleText,
            name="RPC Login:",
            value="",
            begin_entry_at=self.name_size,
            relx=self.indent,
        )
        self.expose_rpc_port.addVisibleWhenSelected(self.rpc_login)
        self.configure_monero_node.addVisibleWhenSelected(self.rpc_login)
        self.nextrely += 1
        self.limit_data_rates = self.add(
            PatchedFormControlCheckbox,
            name="Limit Data Rates",
            value=False,
            begin_entry_at=self.name_size,
            relx=self.indent,
        )
        self.configure_monero_node.addVisibleWhenSelected(self.limit_data_rates)
        self.rate_limit_up = self.add(
            npyscreen.TitleText,
            name="Rate Limit Up:",
            value="2048",
            begin_entry_at=self.name_size,
            relx=self.indent,
        )
        self.limit_data_rates.addVisibleWhenSelected(self.rate_limit_up)
        self.configure_monero_node.addVisibleWhenSelected(self.rate_limit_up)
        self.rate_limit_down = self.add(
            npyscreen.TitleText,
            name="Rate Limit Down:",
            value="8192",
            begin_entry_at=self.name_size,
            relx=self.indent,
        )
        self.limit_data_rates.addVisibleWhenSelected(self.rate_limit_down)
        self.configure_monero_node.addVisibleWhenSelected(self.rate_limit_down)
        self.nextrely += 1
        self.sync_pruned_blocks = self.add(
            npyscreen.Checkbox,
            name="Sync Pruned Blocks",
            value=False,
            begin_entry_at=self.name_size,
            relx=self.indent,
        )
        self.configure_monero_node.addVisibleWhenSelected(self.sync_pruned_blocks)
        self.prune_node.addVisibleWhenSelected(self.sync_pruned_blocks)
        self.fast_sync = self.add(
            npyscreen.Checkbox,
            name="Fast Block Sync",
            value=False,
            begin_entry_at=self.name_size,
            relx=self.indent,
        )
        self.configure_monero_node.addVisibleWhenSelected(self.fast_sync)
        self.nextrely += 1
        self.public_node = self.add(
            npyscreen.TitleText,
            name="Public Node:",
            value="",
            begin_entry_at=self.name_size,
            relx=self.indent,
        )
        self.configure_monero_node.addInvisibleWhenSelected(self.public_node)
        self.node_login = self.add(
            npyscreen.TitleText,
            name="Node Login:",
            value="",
            begin_entry_at=self.name_size,
            relx=self.indent,
        )
        self.configure_monero_node.addInvisibleWhenSelected(self.node_login)
        self.nextrely += 1
        self.monero_extra = self.add(
            npyscreen.TitleText,
            name="Additional monerod Options:",
            value="",
            begin_entry_at=self.name_size + 10,
            relx=self.indent,
        )
        self.configure_monero_node.addVisibleWhenSelected(self.monero_extra)
        self.nextrely += 1
        self.nextrely += 1
        # Add "Prev", "Next", "Save", and "Cancel" buttons
        self.prev_button = self.add(PrevButton, name="Prev", relx=1)
        self.nextrely -= 1
        self.next_button = self.add(NextButton, name="Next", relx=8)
        self.nextrely -= 1
        self.save_button = self.add(SaveButton, name="Save", relx=15)
        self.nextrely -= 1
        self.cancel_button = self.add(CancelButton, name="Cancel", relx=22)
        self.nextrely += 1
        # Add Help Box
        self.help = self.add(
            MoneroHelpBox,
            name="Commands:  ^D: Load Defaults  -  ^C: Exit Without Saving",
            values=[""],
            editable=False,
        )
        # Start with current config
        self.set_config(self.get_current_config())

    def prev_form(self):
        self.find_parent_app().switchForm("MAIN")

    def next_form(self):
        self.find_parent_app().switchForm("XMRIG")

    def set_config(self, config):
        self.configure_monero_node.set_value(config["configure_monero"])
        self.monero_git_tag.set_value(config["monero_version"])
        self.prune_node.value = config["prune_blockchain"]
        self.monero_log_level.set_value(config["monero_log_level"])
        self.expose_rpc_port.set_value(config["expose_rpc_port"])
        self.rpc_port.set_value(config["rpc_port"])
        self.rpc_login.set_value(config["rpc_login"])
        self.limit_data_rates.set_value(config["limit_data_rates"])
        self.rate_limit_up.set_value(config["rate_limit_up"])
        self.rate_limit_down.set_value(config["rate_limit_down"])
        self.sync_pruned_blocks.value = config["sync_pruned_blocks"]
        self.fast_sync.value = config["fast_sync"]
        self.monero_extra.set_value(config["monero_options"])
        self.public_node.set_value(config["public_monero_node"])
        self.node_login.set_value(config["monero_node_login"])
        self.DISPLAY()

    def get_config(self):
        config = {
            "configure_monero": self.configure_monero_node.value,
            "monero_version": self.monero_git_tag.value,
            "prune_blockchain": self.prune_node.value,
            "monero_log_level": self.monero_log_level.value,
            "expose_rpc_port": self.expose_rpc_port.value,
            "rpc_port": self.rpc_port.value,
            "rpc_login": self.rpc_login.value,
            "limit_data_rates": self.limit_data_rates.value,
            "rate_limit_up": self.rate_limit_up.value,
            "rate_limit_down": self.rate_limit_down.value,
            "sync_pruned_blocks": self.sync_pruned_blocks.value,
            "fast_sync": self.fast_sync.value,
            "monero_options": self.monero_extra.value,
            "public_monero_node": self.public_node.value,
            "monero_node_login": self.node_login.value,
        }
        return config


##
# XMRig Configuration Form
class XMRigConfigForm(ConfigFormBase):
    def create(self):
        # Add Hot-Key Controls
        self.add_handlers({"^D": self.reset_defaults})
        # Hidden caryover from P2Pool form
        self.autodiff = self.add(
            PatchedFormControlCheckbox,
            name="Enable Autodiff",
            value=True,
            begin_entry_at=self.name_size,
            relx=self.indent,
        )
        self.autodiff.hide = True
        self.autodiff.editable = False
        self.nextrely -= 1
        # Add XMRig Configuration
        self.add(
            npyscreen.TitleText,
            name="## XMRig Miner Configuration",
            editable=False,
            begin_entry_at=50,
        )
        self.configure_xmrig_miner = self.add(
            PatchedFormControlCheckbox,
            name="Configure XMRig CPU Miner",
            value=True,
            relx=self.indent,
        )
        self.nextrely += 1
        self.username = self.add(
            npyscreen.TitleText,
            name="Username:",
            value="",
            begin_entry_at=self.name_size,
            relx=self.indent,
        )
        self.configure_xmrig_miner.addVisibleWhenSelected(self.username)
        self.nextrely += 1
        self.use_fixed_difficulty = self.add(
            PatchedFormControlCheckbox,
            name="Use Fixed Difficulty",
            value=True,
            relx=self.indent,
        )
        self.configure_xmrig_miner.addVisibleWhenSelected(self.use_fixed_difficulty)
        self.autodiff.addInvisibleWhenSelected(self.use_fixed_difficulty)
        self.fixed_difficulty = self.add(
            TitleIntegerSlider,
            name="Fixed Difficulty:",
            out_of=2000000,
            value=500000,
            lowest=50000,
            step=50000,
            width=51,
            begin_entry_at=20,
            label=True,
            relx=self.indent,
        )
        self.configure_xmrig_miner.addVisibleWhenSelected(self.fixed_difficulty)
        self.use_fixed_difficulty.addVisibleWhenSelected(self.fixed_difficulty)
        self.autodiff.addInvisibleWhenSelected(self.fixed_difficulty)
        self.nextrely += 1
        self.cpu_threads = self.add(
            TitleIntegerSlider,
            name="CPU Use %:",
            out_of=100,
            value=100,
            lowest=1,
            step=10,
            width=48,
            begin_entry_at=20,
            label=True,
            relx=self.indent,
        )
        self.configure_xmrig_miner.addVisibleWhenSelected(self.cpu_threads)
        self.nextrely += 1
        self.cpu_priority = self.add(
            TitleIntegerSlider,
            name="CPU Priority:",
            out_of=5,
            value=2,
            lowest=0,
            step=1,
            width=48,
            begin_entry_at=20,
            label=True,
            relx=self.indent,
        )
        self.configure_xmrig_miner.addVisibleWhenSelected(self.cpu_priority)
        self.nextrely += 1
        self.xmrig_extra = self.add(
            npyscreen.TitleText,
            name="Additional XMRig Options:",
            value="",
            begin_entry_at=self.name_size + 10,
            relx=self.indent,
        )
        self.configure_xmrig_miner.addVisibleWhenSelected(self.xmrig_extra)
        self.nextrely += 1
        self.nextrely += 1
        # Add "Prev", "Save", and "Cancel" buttons
        self.prev_button = self.add(PrevButton, name="Prev", relx=1)
        self.nextrely -= 1
        self.save_button = self.add(SaveButton, name="Save", relx=8)
        self.nextrely -= 1
        self.cancel_button = self.add(CancelButton, name="Cancel", relx=15)
        self.nextrely += 1
        # Add Help Box
        self.help = self.add(
            XMRigHelpBox,
            name="Commands:  ^D: Load Defaults  -  ^C: Exit Without Saving",
            values=[""],
            editable=False,
        )
        # Start with current config
        self.set_config(self.get_current_config())

    def prev_form(self):
        self.find_parent_app().switchForm("MONERO")

    def next_form(self):
        self.find_parent_app().switchForm(None)

    def beforeEditing(self):
        # Cary autodiff value from P2Pool config form
        enable_autodiff = self.find_parent_app().get_p2pool_config()["enable_autodiff"]
        self.autodiff.set_value(enable_autodiff)

    def set_config(self, config):
        self.configure_xmrig_miner.set_value(config["configure_xmrig"])
        self.username.set_value(config["xmrig_username"])
        self.use_fixed_difficulty.set_value(config["use_fixed_difficulty"])
        self.fixed_difficulty.set_value(config["fixed_difficulty"])
        self.cpu_threads.set_value(config["cpu_percent"])
        self.cpu_priority.set_value(config["cpu_priority"])
        self.xmrig_extra.set_value(config["xmrig_options"])
        self.DISPLAY()

    def get_config(self):
        config = {
            "configure_xmrig": self.configure_xmrig_miner.value,
            "xmrig_username": self.username.value,
            "use_fixed_difficulty": self.use_fixed_difficulty.value,
            "fixed_difficulty": self.fixed_difficulty.value,
            "cpu_percent": self.cpu_threads.value,
            "cpu_priority": self.cpu_priority.value,
            "xmrig_options": self.xmrig_extra.value,
        }
        return config


##
# Our P2Pool configuration App
class ConfigApp(npyscreen.NPSAppManaged):
    current_config = None
    defaults = None

    def onStart(self):
        self.p2pool_form = self.addForm(
            "MAIN",
            P2PoolConfigForm,
            name="P2Pool for docker-compose: P2Pool Configuration",
            minimum_lines=35,
            minimum_columns=80,
        )
        self.monero_form = self.addForm(
            "MONERO",
            MoneroConfigForm,
            name="P2Pool for docker-compose: Monero Configuration",
            minimum_lines=35,
            minimum_columns=80,
        )
        self.xmrig_form = self.addForm(
            "XMRIG",
            XMRigConfigForm,
            name="P2Pool for docker-compose: XMRig Configuration",
            minimum_lines=35,
            minimum_columns=80,
        )

    def get_p2pool_config(self):
        return self.p2pool_form.get_config()

    def get_config(self):
        p2pool_config = self.p2pool_form.get_config()
        monero_config = self.monero_form.get_config()
        xmrig_config = self.xmrig_form.get_config()
        return p2pool_config | monero_config | xmrig_config

    def save_and_exit(self):
        # Get config from all forms
        config = self.get_config()
        # Save "current config" values file
        with open("current_config.jinja2", "r") as current_config:
            template = current_config.read()
        rendered = Template(template).render(config)
        with open("/docker-compose/current_config", "w") as current_config:
            current_config.write(rendered)
        # Render and save docker-compose file
        with open("docker-compose.jinja2", "r") as compose_file:
            template = compose_file.read()
        rendered = Template(template).render(config, trim_blocks=True)
        with open("/docker-compose/docker-compose.yml", "w") as compose_file:
            compose_file.write(rendered)
        npyscreen.notify("Saved current settings", title="Saved")
        self.switchForm(None)
        self.saved = True

    def cancel_and_exit(self):
        self.switchForm(None)
        self.saved = False


##


if __name__ == "__main__":
    try:
        time.sleep(1)  # Give docker a second to initialize the terminal
        App = ConfigApp()
        App.run()
        print("\n\n")
        if App.saved:
            print("Configuration Saved")
        else:
            print("Configuration Aborted")
            sys.exit(1)
    except KeyboardInterrupt:
        print("Configuration Aborted")
        sys.exit(1)

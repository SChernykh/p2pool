#!/bin/env python3
import time
import json
from jinja2 import Template
import npyscreen


def load_default_config():
    # Read defaults
    with open("defaults") as defaults_file:
        defaults = json.load(defaults_file)
    return defaults


def load_current_config():
    # Read current config
    with open("/docker-compose/current_config") as current_config:
        config = json.load(current_config)
    return config


##
# Help text in a box at the bottom of the screen
class HelpBox(npyscreen.BoxTitle):
    def display_help_message(self, field):
        if field == "Configure Monero Node":
            self.set_values(
                [
                    "Configure and run a Monero Node",
                    "",
                    "Note: You must either configure a local node or specify a public node",
                ]
            )
        elif field == "Configure XMRig CPU Miner":
            self.set_values(
                [
                    "Configure and run an XMRig CPU Miner",
                    "",
                    "Note: You must either configure am XMRig CPU Miner or expose the",
                    "      P2Pool stratum port and connect an external miner, or both",
                ]
            )
        elif field == "Wallet Address:":
            self.set_values(
                [
                    "Your monero wallet address for receiving mining reqards",
                    "",
                    "Note: You have to use a primary wallet address for mining",
                    "      Subaddresses and integrated addresses are not supported!",
                ]
            )
        elif field == "P2Pool Sidechain:":
            self.set_values(
                [
                    "Which P2Pool sidechain to mine on",
                    "    use main for faster miners",
                    "    use mini for slower miners",
                ]
            )
        elif field == "Expose Stratum Port":
            self.set_values(
                [
                    "Expose the P2Pool stratum port to your network so external miners",
                    "can connect",
                    "Note: You may choose to open this port in your hosts firewall and/or",
                    "      router to allow miners outside your network to connect",
                ]
            )
        elif field == "Stratum Port:":
            self.set_values(
                [
                    "Port number to expose P2Pool stratum to your network to allow",
                    "external miners to connect",
                ]
            )
        elif field == "P2Pool Log Level:":
            self.set_values(["Verbosity of the log; (Less) 0 - 6 (More)"])
        elif field == "Enable Autodiff":
            self.set_values(
                ["Use automatic difficulty adjustment for miners connected to stratum"]
            )
        elif field == "Additional P2Pool Options:":
            self.set_values(
                [
                    "Additional options to pass to p2pool commandline",
                    "",
                    "Note: Advanced - Only add options if you know what you are doing",
                    "      See ouput of 'p2pool --help' for available options",
                ]
            )
        elif field == "Monero Version:":
            self.set_values(
                [
                    "Version of Monero to build; 'latest' for the most recent release",
                    "",
                    "Note: Must be v0.17.3.0 or later for p2pool support",
                    "      See: https://github.com/monero-project/monero/tags",
                ]
            )
        elif field == "Prune Blockchain":
            self.set_values(
                ["Prune the Monero node to limit the size of the blockchain on disk"]
            )
        elif field == "Monero Log Level:":
            self.set_values(["Verbosity of the log; (Less) 0 - 4 (More)"])
        elif field == "Additional monerod Options:":
            self.set_values(
                [
                    "Additional options to pass to monerod commandline",
                    "",
                    "Note: Advanced - Only add options if you know what you are doing",
                    "      See 'https://monerodocs.org/interacting/monerod-reference/'",
                ]
            )
        elif field == "Public Node:":
            self.set_values(
                [
                    "Public Monero Node to Use",
                    "",
                    "Note: The public node must have both Monero RPC and zmq-pub ports",
                    "      available",
                ]
            )
        elif field == "Node Login:":
            self.set_values(
                [
                    "Specify username[:password] required to connect to public monero",
                    "node RPC API (if required)"
                ]
            )
        elif field == "Username:":
            self.set_values(["Set a username for the miner"])
        elif field == "Use Fixed Difficulty":
            self.set_values(
                [
                    "Used a fixed minig difficulty",
                    "",
                    "Note: Allows you to see XMRig submitting shares below P2Pool threshold",
                ]
            )
        elif field == "Fixed Difficulty:":
            self.set_values(
                [
                    "Set a fixed mining difficulty",
                    "",
                    "Note: Allows you to see XMRig submitting shares below P2Pool threshold",
                ]
            )
        elif field == "CPU Use %:":
            self.set_values(
                ["maximum CPU threads count (in percentage) hint for autoconfig"]
            )
        elif field == "Additional XMRig Options:":
            self.set_values(
                [
                    "Additional options to pass to xmrig",
                    "",
                    "Note: Advanced - Only add options if you know what you are doing",
                    "      See 'https://xmrig.com/docs/miner/command-line-options'",
                ]
            )
        elif field == "Save":
            self.set_values(["Save current configuration"])
        elif field == "Cancel":
            self.set_values(["Exit without saving"])
        self.clear()
        self.display()


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


class SaveButton(npyscreen.Button):
    def whenToggled(self):
        self.parent.save_and_exit()


class CancelButton(npyscreen.Button):
    def whenToggled(self):
        self.parent.cancel_and_exit()


##
# Configuration Form
class ConfigForm(npyscreen.FormBaseNew):
    ALLOW_RESIZE = False
    name_size = 20
    indent = 5

    def while_editing(self, arg):
        self.help.display_help_message(arg.name)

    def create(self):
        # Add Hot-Key Controls
        self.add_handlers({"^D": self.load_defaults})
        # Add Global Configuration
        self.add(
            npyscreen.TitleText,
            name="## General Configuration",
            editable=False,
            begin_entry_at=50,
        )
        self.configure_monero_node = self.add(
            PatchedFormControlCheckbox,
            name="Configure Monero Node",
            value=True,
            relx=self.indent,
        )
        self.configure_xmrig_miner = self.add(
            PatchedFormControlCheckbox,
            name="Configure XMRig CPU Miner",
            value=True,
            relx=self.indent,
        )
        self.nextrely += 1
        self.nextrely += 1
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
        self.autodiff = self.add(
            PatchedFormControlCheckbox,
            name="Enable Autodiff",
            value=True,
            begin_entry_at=self.name_size,
            relx=self.indent,
        )
        self.p2pool_extra = self.add(
            npyscreen.TitleText,
            name="Additional P2Pool Options:",
            value="",
            begin_entry_at=self.name_size + 10,
            relx=self.indent,
        )
        self.nextrely += 1
        self.nextrely += 1
        # Add Monero Configuration
        self.add(
            npyscreen.TitleText,
            name="## Monero Node Configuration",
            editable=False,
            begin_entry_at=50,
        )
        self.monero_git_tag = self.add(
            npyscreen.TitleText,
            name="Monero Version:",
            value="latest",
            begin_entry_at=self.name_size,
            relx=self.indent,
        )
        self.configure_monero_node.addVisibleWhenSelected(self.monero_git_tag)
        self.prune_node = self.add(
            npyscreen.Checkbox,
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
        self.monero_extra = self.add(
            npyscreen.TitleText,
            name="Additional monerod Options:",
            value="",
            begin_entry_at=self.name_size + 10,
            relx=self.indent,
        )
        self.configure_monero_node.addVisibleWhenSelected(self.monero_extra)
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
        self.nextrely += 1
        # Add XMRig Configuration
        self.add(
            npyscreen.TitleText,
            name="## XMRig Miner Configuration",
            editable=False,
            begin_entry_at=50,
        )
        self.username = self.add(
            npyscreen.TitleText,
            name="Username:",
            value="",
            begin_entry_at=self.name_size,
            relx=self.indent,
        )
        self.configure_xmrig_miner.addVisibleWhenSelected(self.username)
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
        # Add "Save" button
        self.save_button = self.add(SaveButton, name="Save", relx=1)
        self.nextrely -= 1
        self.cancel_button = self.add(CancelButton, name="Cancel", relx=8)
        self.nextrely += 1
        # Add Help Box
        self.help = self.add(
            HelpBox,
            name="Commands:  ^D: Load Defaults  -  ^C: Exit Without Saving",
            values=[""],
            rely=-8,
            editable=False,
        )
        # Start with current config
        self.set_config(load_current_config())

    def set_config(self, config):
        self.configure_monero_node.set_value(config["configure_monero"])
        self.configure_xmrig_miner.set_value(config["configure_xmrig"])
        self.wallet_address.set_value(config["wallet_address"])
        self.sidechain.set_value(config["sidechain"])
        self.expose_stratum_port.set_value(config["expose_stratum_port"])
        self.stratum_port.set_value(config["stratum_port"])
        self.p2pool_log_level.set_value(config["p2pool_log_level"])
        self.autodiff.set_value(config["enable_autodiff"])
        self.p2pool_extra.set_value(config["p2pool_options"])
        self.monero_git_tag.set_value(config["monero_version"])
        self.prune_node.value = config["prune_blockchain"]
        self.monero_log_level.set_value(config["monero_log_level"])
        self.monero_extra.set_value(config["monero_options"])
        self.public_node.set_value(config["public_monero_node"])
        self.node_login.set_value(config["monero_node_login"])
        self.username.set_value(config["xmrig_username"])
        self.use_fixed_difficulty.set_value(config["use_fixed_difficulty"])
        self.fixed_difficulty.set_value(config["fixed_difficulty"])
        self.cpu_threads.set_value(config["cpu_percent"])
        self.xmrig_extra.set_value(config["xmrig_options"])
        self.DISPLAY()

    def get_config(self):
        config = {
            "configure_monero": self.configure_monero_node.value,
            "configure_xmrig": self.configure_xmrig_miner.value,
            "wallet_address": self.wallet_address.value,
            "sidechain": self.sidechain.value,
            "expose_stratum_port": self.expose_stratum_port.value,
            "stratum_port": self.stratum_port.value,
            "p2pool_log_level": self.p2pool_log_level.value,
            "enable_autodiff": self.autodiff.value,
            "p2pool_options": self.p2pool_extra.value,
            "monero_version": self.monero_git_tag.value,
            "prune_blockchain": self.prune_node.value,
            "monero_log_level": self.monero_log_level.value,
            "monero_options": self.monero_extra.value,
            "public_monero_node": self.public_node.value,
            "monero_node_login": self.node_login.value,
            "xmrig_username": self.username.value,
            "use_fixed_difficulty": self.use_fixed_difficulty.value,
            "fixed_difficulty": self.fixed_difficulty.value,
            "cpu_percent": self.cpu_threads.value,
            "xmrig_options": self.xmrig_extra.value,
        }
        return config

    # Control methods
    def load_defaults(self, arg):
        ok = npyscreen.notify_ok_cancel(
            "Set all values to defaults", title="Load Defaults"
        )
        if not ok:
            return
        defaults = load_default_config()
        self.set_config(defaults)

    def save_and_exit(self):
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
        self.find_parent_app().switchForm(None)
        self.find_parent_app().saved = True

    def cancel_and_exit(self):
        self.find_parent_app().switchForm(None)
        self.find_parent_app().saved = False


##
# Our P2Pool configuration App
class ConfigApp(npyscreen.NPSAppManaged):
    def onStart(self):
        self.f = self.addForm(
            "MAIN",
            ConfigForm,
            name="P2Pool for docker-compose: Global Configuration",
            lines=45,
            columns=80,
            minimum_lines=45,
            minimum_columns=80,
        )


if __name__ == "__main__":
    try:
        time.sleep(1)  # Give docker a second to initialize the terminal
        App = ConfigApp()
        App.run()
        print("\n\n")
        if App.saved:
            print("Configuration Saved")
            print(
                'Run "docker compose up -d" to start (if you are using the docker-compose plugin'
            )
            print(
                'or, "docker-compose up -d" (if you are using pip installed docker-compose)'
            )
        else:
            print("Configuration Aborted")
    except KeyboardInterrupt:
        print("Configuration Aborted")

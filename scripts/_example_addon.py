"""Example custom mitmproxy addon for pRoxy.

This file is IGNORED by the auto-loader (its name starts with "_"). Copy it to a
name without the underscore (e.g. my_addon.py) to activate it, or add its path to
the `custom_scripts` setting.

Full hook reference: https://docs.mitmproxy.org/stable/addons-overview/
"""
import logging

logger = logging.getLogger("pRoxy.script.example")


class ExampleAddon:
    def request(self, flow):
        # Tag every outgoing request so you can see the addon is active.
        flow.request.headers["X-pRoxy-Example"] = "1"

    def response(self, flow):
        logger.info("example addon: %s -> %s",
                    flow.request.pretty_url, flow.response.status_code)


addons = [ExampleAddon()]

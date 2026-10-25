"""Private mitmproxy addon: readiness after local redirector initialization."""
import asyncio
import json
import logging
import os
from pathlib import Path
import time

from mitmproxy import ctx
from mitmproxy.proxy.mode_specs import LocalMode


class TelemetryRadarControl:
    def __init__(self):
        self.started = False
        self.last_status = None
        self.last_published_at = 0.0
        self.heartbeat = 0

    def load(self, loader):
        self.directory = Path(os.environ["TELEMETRYRADAR_MITM_CONTROL"])
        config = json.loads((self.directory / "desired.json").read_text("utf-8"))
        if config["allow_hosts"] is not None:
            ctx.options.update(allow_hosts=config["allow_hosts"])
        self.task = asyncio.create_task(self.watch())

    def running(self):
        # Master calls running only AFTER setup_servers, including UAC/sudo.
        self.started = True

    def publish(self, phase, mode, error=None):
        value = {"phase": phase, "mode": mode, "error": error}
        now = time.monotonic()
        if value == self.last_status and now - self.last_published_at < 1.0:
            return
        self.heartbeat += 1
        path = self.directory / "status.tmp"
        path.write_text(json.dumps({**value, "heartbeat": self.heartbeat}), encoding="utf-8")
        path.replace(self.directory / "status.json")
        self.last_status = value
        self.last_published_at = now

    async def watch(self):
        try:
            while True:
                if (self.directory / "stop").exists():
                    ctx.master.shutdown()
                    return
                desired = json.loads((self.directory / "desired.json").read_text("utf-8"))
                mode = desired["mode"]
                if self.started:
                    proxy = ctx.master.addons.get("proxyserver")
                    if not proxy:
                        raise RuntimeError("mitmproxy proxyserver addon is unavailable")
                    if list(ctx.options.mode) != [mode]:
                        self.publish("starting", mode)
                        ctx.options.update(mode=[mode])
                        await asyncio.sleep(0.1)
                        continue
                    servers = list(proxy.servers)
                    if (len(servers) == 1 and isinstance(servers[0].mode, LocalMode)
                            and servers[0].mode.full_spec == mode
                            and servers[0].is_running and not proxy.servers.is_updating):
                        self.publish("ready", mode)
                    elif any(server.last_exception for server in servers):
                        raise RuntimeError("local redirector failed to initialize")
                    elif not proxy.servers.is_updating:
                        raise RuntimeError("local redirector is no longer running")
                await asyncio.sleep(0.1)
        except asyncio.CancelledError:
            return
        except Exception as error:
            try:
                self.publish("failed", "", str(error))
            except OSError:
                logging.exception("Cannot publish local-capture failure status")
            finally:
                # A broken status directory must not leave an uncontrolled proxy
                # running behind a stale 'ready' message.
                ctx.master.shutdown()

    def done(self):
        self.task.cancel()


addons = [TelemetryRadarControl()]

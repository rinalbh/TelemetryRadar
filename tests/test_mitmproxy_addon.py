"""Readiness checks with real mitmproxy mode parsing and a simulated UAC wait."""
import asyncio
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from mitmproxy.proxy.mode_specs import LocalMode
from mitmproxy.certs import CertStore

SOURCE = Path(__file__).parents[1] / "src/mitmproxy/control_addon.py"
spec = importlib.util.spec_from_file_location("radar_control", SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class Servers(list):
    is_updating = False


class CertificateIsolationTests(unittest.TestCase):
    def test_mitmproxy_generates_different_cas_in_capture_specific_directories(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            CertStore.from_store(Path(first), "mitmproxy", 2048)
            CertStore.from_store(Path(second), "mitmproxy", 2048)
            ca1 = (Path(first) / "mitmproxy-ca-cert.pem").read_bytes()
            ca2 = (Path(second) / "mitmproxy-ca-cert.pem").read_bytes()
            self.assertNotEqual(ca1, ca2)
            self.assertNotIn(b"PRIVATE KEY", ca1)
            self.assertIn(b"PRIVATE KEY", (Path(first) / "mitmproxy-ca.pem").read_bytes())


class ReadinessTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.mode = "local:999999999"
        (self.directory / "desired.json").write_text(json.dumps({
            "mode": self.mode, "allow_hosts": None,
        }))
        self.server = SimpleNamespace(mode=LocalMode.parse(self.mode),
                                      is_running=True, last_exception=None)
        self.servers = Servers([self.server])
        self.stopped = asyncio.Event()
        self.options = SimpleNamespace(mode=[self.mode])
        self.options.update = lambda **values: self.options.__dict__.update(values)
        self.context = SimpleNamespace(options=self.options, master=SimpleNamespace(
            addons=SimpleNamespace(get=lambda name: SimpleNamespace(servers=self.servers)),
            shutdown=self.stopped.set,
        ))
        self.patches = [patch.object(module, "ctx", self.context),
                        patch.dict(os.environ, TELEMETRYRADAR_MITM_CONTROL=str(self.directory))]
        for item in self.patches:
            item.start()
        self.addon = module.TelemetryRadarControl()
        self.addon.load(None)

    async def asyncTearDown(self):
        self.addon.done()
        await self.addon.task
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    async def status(self):
        for _ in range(30):
            path = self.directory / "status.json"
            if path.exists():
                return json.loads(path.read_text())
            await asyncio.sleep(0.02)
        self.fail("status was not published")

    async def test_waits_through_permission_prompt_until_running_hook(self):
        await asyncio.sleep(0.25)
        self.assertFalse((self.directory / "status.json").exists())
        self.addon.running()
        self.assertEqual((await self.status())["phase"], "ready")
        (self.directory / "stop").touch()
        await asyncio.wait_for(self.stopped.wait(), 1)

    async def test_unrestricted_local_mode_becomes_ready(self):
        self.mode = "local"
        self.server.mode = LocalMode.parse(self.mode)
        self.options.mode = [self.mode]
        (self.directory / "desired.json").write_text(json.dumps({
            "mode": self.mode, "allow_hosts": None,
        }))
        self.addon.running()
        status = await self.status()
        self.assertEqual(status["phase"], "ready")
        self.assertEqual(status["mode"], "local")

    async def test_running_hook_without_active_local_server_is_not_ready(self):
        self.server.is_running = False
        self.addon.running()
        self.assertEqual((await self.status())["phase"], "failed")
        self.assertTrue(self.stopped.is_set())

    async def test_no_ready_while_server_update_is_pending(self):
        self.servers.is_updating = True
        self.addon.running()
        await asyncio.sleep(0.25)
        self.assertFalse((self.directory / "status.json").exists())
        self.servers.is_updating = False
        self.assertEqual((await self.status())["phase"], "ready")

    async def test_runtime_server_loss_is_reported(self):
        self.addon.running()
        self.assertEqual((await self.status())["phase"], "ready")
        self.server.is_running = False
        await asyncio.wait_for(self.stopped.wait(), 1)
        value = json.loads((self.directory / "status.json").read_text())
        self.assertEqual(value["phase"], "failed")

    async def test_ready_heartbeat_keeps_advancing_without_configuration_changes(self):
        self.addon.running()
        first = await self.status()
        await asyncio.sleep(1.2)
        second = json.loads((self.directory / "status.json").read_text())
        self.assertGreater(second["heartbeat"], first["heartbeat"])

    async def test_status_write_failure_still_stops_the_proxy(self):
        with patch.object(self.addon, "publish", side_effect=OSError("disk unavailable")):
            with self.assertLogs(level="ERROR"):
                self.addon.running()
                await asyncio.wait_for(self.stopped.wait(), 1)


if __name__ == "__main__":
    unittest.main()

"""Gates (i) refusal and (ii) side-by-side, against live components and no mocks.

Stands up HiveMQ CE (docker compose), the Bifrost OPC UA sim, a mapping registry published with Bifrost's CLI and
fresh keys, Muninn ``feed --session --hierarchy``, and Vor over MCP stdio driven by a real MCP client. An OPC UA client
reads the sim directly and writes its status-control node.

    python scripts/vor_gate.py [--bifrost ../bifrost] [--muninn ../muninn] [--negative-control]

Needs ``<bifrost>/{gates,sim}/target/*.jar`` and ``<muninn>/target/muninn.jar``, Docker, Java 17+, and the ``gate``
extra (``pip install -e ".[gate]"``). Exit 0 only when every assertion ran and held. ``--negative-control`` expects a
usable answer under Bad quality, so the gate must fail (exit 1): that run proves the assertions can fail.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "scripts"), str(ROOT / "tests")]

from make_fixtures import Gates, Publisher, vor_read_source  # noqa: E402
from helpers import Keys, sign_head, statement_of  # noqa: E402

ENDPOINT, NS_URI = "opc.tcp://localhost:48400", "urn:bifrost:opcua:sim"
TEMP_NODE, TEMP_STATUS = "Line1/Mixer1.Temp", "Sim/Line1/Mixer1.Temp.StatusCode"
MQTT, GROUP, EDGE = "tcp://localhost:1883", "Bifrost:Line1", "recipe-edge"
QUESTION, BINDING = "mixer1-temp", "vor-binding-mixer1-temp"
BAD = 0x80020000  # BadInternalError
EXPECTED_ASSERTIONS = 9


class GateFailure(Exception):
    pass


class Gate:
    def __init__(self, negative_control: bool):
        self.negative_control = negative_control
        self.assertions = 0
        self.previous: str | None = None

    def check(self, label: str, ok: bool, detail) -> None:
        self.assertions += 1
        print(f"[GATE] {'PASS' if ok else 'FAIL'} {label}", flush=True)
        if not ok:
            raise GateFailure(f"{label}: {json.dumps(detail, default=str)[:2000]}")

    def outcome(self, out: dict) -> str:
        v = out["verdict"]
        return "usable" if v["usable"] else v["reason"]

    def transition(self, label: str, out: dict, expected: str) -> None:
        """One step of the refusal lifecycle: the expected outcome, and a different one from the step before."""
        got = self.outcome(out)
        self.check(f"{label}: {got} (expected {expected}, previous {self.previous})",
                   got == expected and got != self.previous, out)
        self.previous = got


def log_has(path: Path, text: str) -> bool:
    return path.exists() and text in path.read_text(encoding="utf-8", errors="replace")


def wait_for(what: str, predicate, timeout: float, step: float = 0.5) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(step)
    raise GateFailure(f"timed out after {timeout:.0f}s waiting for {what}")


def run(*cmd: str, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(list(cmd), capture_output=True, text=True, **kw)


class Stack:
    """The live components; every process and the broker are stopped on exit, pass or fail."""

    def __init__(self, bifrost: Path, muninn: Path, work: Path):
        self.work, self.procs = work, []
        self.gates_jar = bifrost / "gates" / "target" / "bifrost-gates.jar"
        self.sim_jar = bifrost / "sim" / "target" / "bifrost-sim.jar"
        self.muninn_jar = muninn / "target" / "muninn.jar"
        self.recipe = muninn / "scripts" / "fixtures" / "Line1-Mixer-1.0.0.json"
        self.source = vor_read_source(bifrost)
        for f in (self.gates_jar, self.sim_jar, self.muninn_jar, self.recipe, self.source):
            if not f.exists():
                raise GateFailure(f"missing {f} (build Bifrost and Muninn first)")
        self.compose = ROOT / "docker-compose.yml"

    def start(self, name: str, *cmd: str) -> Path:
        log = self.work / f"{name}.log"
        # Own process group, so stop() can end the whole tree: `java` is often a launcher that starts the real JVM.
        group = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
        self.procs.append(subprocess.Popen(list(cmd), stdout=log.open("w"), stderr=subprocess.STDOUT, **group))
        return log

    def broker(self) -> None:
        if shutil.which("docker") is None:
            raise GateFailure("docker not found on PATH")
        run("docker", "rm", "-f", "vor-hivemq-ce", "muninn-hivemq-ce", "bifrost-hivemq-ce")
        r = run("docker", "compose", "-f", str(self.compose), "up", "-d", "hivemq-ce")
        if r.returncode != 0:
            raise GateFailure(f"broker did not start: {r.stderr}")
        def started() -> bool:
            r = run("docker", "logs", "vor-hivemq-ce")
            return "Started HiveMQ" in r.stdout + r.stderr

        wait_for("HiveMQ to start", started, 90, 1)

    def sim(self) -> None:
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", 48400)) == 0:
                raise GateFailure("port 48400 is already in use (a sim from an earlier run?)")
        log = self.start("sim", "java", "-jar", str(self.sim_jar))
        wait_for("the OPC UA sim", lambda: log_has(log, "OPC-UA sim listening"), 60)

    def recipe_registry(self) -> Path:
        src, reg = self.work / "srcrepo", self.work / "recipe-registry"
        src.mkdir()
        shutil.copyfile(self.recipe, src / self.recipe.name)
        for cmd in (["init", "-q"], ["add", "."], ["commit", "-qm", "seed"]):
            r = run("git", "-c", "user.email=gate@local", "-c", "user.name=gate", "-C", str(src), *cmd)
            if r.returncode != 0:
                raise GateFailure(f"git {cmd[0]}: {r.stderr}")
        r = run("java", "-jar", str(self.gates_jar), "provenance", "publish", str(reg), str(src), self.recipe.name,
                "Line1-Mixer", "1.0.0")
        if r.returncode != 0:
            raise GateFailure(f"provenance publish failed: {r.stdout}{r.stderr}")
        return reg

    def feed(self, recipes: Path, mappings: Path) -> Path:
        log = self.start("muninn", "java", "-jar", str(self.muninn_jar), "feed", str(recipes), "Line1-Mixer", "1.0.0",
                         ENDPOINT, NS_URI, "Line1/Mixer1", MQTT, GROUP, EDGE,
                         "--hierarchy", str(mappings), "line1", "mixer1", "--session", "1000")
        wait_for("the Muninn session", lambda: log_has(log, "session up"), 60)
        return log

    def rebirth(self) -> None:
        r = run("java", "-jar", str(self.muninn_jar), "host", MQTT, "rebirth", GROUP, EDGE)
        if r.returncode != 0:
            raise GateFailure(f"rebirth request failed: {r.stdout}{r.stderr}")

    def stop(self) -> None:
        for p in self.procs:
            if os.name == "nt":
                run("taskkill", "/F", "/T", "/PID", str(p.pid))
            else:
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            p.wait(timeout=30)
        run("docker", "compose", "-f", str(self.compose), "stop", "hivemq-ce")


class Opc:
    """A plain OPC UA client on the sim: the direct read path and the status-control writer."""

    def __init__(self):
        from asyncua import Client
        self.client = Client(ENDPOINT)

    async def __aenter__(self):
        from asyncua import ua
        await self.client.connect()
        ns = await self.client.get_namespace_index(NS_URI)
        self.temp = self.client.get_node(ua.NodeId(TEMP_NODE, ns))
        self.status = self.client.get_node(ua.NodeId(TEMP_STATUS, ns))
        return self

    async def __aexit__(self, *_):
        await self.client.disconnect()

    async def read(self):
        return await self.temp.read_data_value(raise_on_bad_status=False)

    async def set_status(self, code: int) -> None:
        from asyncua import ua
        await self.status.write_value(ua.DataValue(ua.Variant(code, ua.VariantType.UInt32)))


class VorClient:
    def __init__(self, session):
        self.session = session

    async def read(self) -> dict:
        r = await self.session.call_tool("read_governed", {"question_id": QUESTION})
        return json.loads(r.content[0].text)

    async def until(self, gate: Gate, outcome: str, timeout: float, between=None) -> dict:
        """Poll read_governed until it gives `outcome`; `between` runs every few polls (e.g. a rebirth request)."""
        deadline, n, out = time.monotonic() + timeout, 0, None
        while time.monotonic() < deadline:
            out = await self.read()
            if gate.outcome(out) == outcome:
                return out
            n += 1
            if between and n % 6 == 1:
                between()
            await asyncio.sleep(0.5)
        return out


def numbers(doc) -> list:
    if isinstance(doc, bool):
        return []
    if isinstance(doc, (int, float)):
        return [doc]
    if isinstance(doc, dict):
        return [n for v in doc.values() for n in numbers(v)]
    if isinstance(doc, list):
        return [n for v in doc for n in numbers(v)]
    return []


async def side_by_side(gate: Gate, vor: VorClient, opc: Opc) -> None:
    print("[GATE] ===== gate (ii): side by side =====", flush=True)
    direct = await opc.read()
    out = await vor.read()
    v1 = direct.Value.Value
    v2 = (out["answer"] or {}).get("sample", {}).get("value")
    gate.check(f"good: direct {v1} == Vor {v2}, Vor usable with pin, UCUM unit and policy",
               out["verdict"]["usable"] and v1 == v2 and out["answer"]["pin"]["digest_rule"] == "raw-bytes-sha256"
               and out["answer"]["unit"]["system"] == "UCUM" and "maxAgeMs" in out["answer"]["policy"], out)

    await opc.set_status(BAD)
    out = await vor.until(gate, "bad-quality", 15)
    direct = await opc.read()
    expected = "usable" if gate.negative_control else "bad-quality"
    gate.check(f"bad: direct still returns {direct.Value.Value} (status 0x{direct.StatusCode.value:08X}), "
               f"Vor {gate.outcome(out)} with no sample value (expected {expected})",
               direct.Value.Value == v1 and direct.StatusCode.value == BAD and gate.outcome(out) == expected
               and out["answer"] is None and v1 not in numbers(out), out)
    await opc.set_status(0)


async def refusal(gate: Gate, vor: VorClient, opc: Opc, stack: Stack, mappings: Path, pub: Publisher) -> None:
    print("[GATE] ===== gate (i): refusal lifecycle =====", flush=True)
    gate.transition("1 baseline", await vor.until(gate, "usable", 15), "usable")

    await opc.set_status(BAD)
    gate.transition("2 bad quality", await vor.until(gate, "bad-quality", 15), "bad-quality")

    await opc.set_status(0)
    gate.transition("3 recovery", await vor.until(gate, "usable", 15), "usable")

    # An expired head signed now by the gate with the registry's own synthetic keys: Bifrost's CLI refuses a lifetime
    # under one day, and Vor has no clock or check override, so the gate writes the bytes.
    attestation = mappings / "head-attestations" / "line1.dsse.json"
    original = attestation.read_bytes()
    version = statement_of(mappings, "line1")["predicate"]["headVersion"] + 1
    signed = (datetime.now(timezone.utc) - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    sign_head(mappings, "line1", Keys.from_bifrost(pub.keys, "proposer", "approver"), version=version,
              signed_at=signed, lifetime=timedelta(days=1))
    gate.transition("4 head expired", await vor.read(), "head-expired")

    attestation.write_bytes(original)
    pub.add_lifecycle(mappings.parent, ["deprecate", "retire"])
    gate.transition("5 meaning retired", await vor.read(), "meaning-retired")


async def drive(stack: Stack, cfg: Path, mappings: Path, pub: Publisher, gate: Gate) -> None:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(command=sys.executable, args=["-m", "vor.server"],
                                   env={**os.environ, "VOR_CONFIG": str(cfg)})
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        tools = [t.name for t in (await session.list_tools()).tools]
        gate.check(f"MCP lists exactly read_governed ({tools})", tools == ["read_governed"], tools)
        vor = VorClient(session)
        # Vor joined after the edge node's birth, so it has no sample until a rebirth, which it never requests itself.
        out = await vor.until(gate, "usable", 45, between=stack.rebirth)
        gate.check(f"Vor answers usable after a rebirth ({gate.outcome(out)})", gate.outcome(out) == "usable", out)
        async with Opc() as opc:
            await side_by_side(gate, vor, opc)
            await refusal(gate, vor, opc, stack, mappings, pub)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bifrost", type=Path, default=ROOT.parent / "bifrost")
    ap.add_argument("--muninn", type=Path, default=ROOT.parent / "muninn")
    ap.add_argument("--negative-control", action="store_true")
    a = ap.parse_args()
    gate = Gate(a.negative_control)
    work = Path(tempfile.mkdtemp(prefix="vor-gate-"))
    stack = None
    try:
        stack = Stack(a.bifrost.resolve(), a.muninn.resolve(), work)
        print(f"[GATE] work dir {work}", flush=True)
        stack.broker()
        stack.sim()
        recipes = stack.recipe_registry()
        pub = Publisher(Gates(stack.gates_jar), stack.source, work)
        registry = pub.registry(work / "registry")
        (work / "trusted-keys.jsonl").write_text(pub.authorized)
        cfg = work / "vor.json"
        cfg.write_text(json.dumps({"registry": "registry", "trustedKeys": "trusted-keys.jsonl", "stateDir": "state",
                                   "mqtt": MQTT, "questions": {QUESTION: {
                                       "stream": "line1", "binding": BINDING,
                                       "description": "Mixer1 process temperature in Cel"}}}), encoding="utf-8")
        stack.feed(recipes, registry / "mappings")
        asyncio.run(drive(stack, cfg, registry / "mappings", pub, gate))
        if gate.assertions != EXPECTED_ASSERTIONS:
            raise GateFailure(f"{gate.assertions} assertions ran, expected {EXPECTED_ASSERTIONS}")
    except Exception as e:
        while isinstance(e, BaseExceptionGroup) and len(e.exceptions) == 1:  # the MCP client's task group wraps it
            e = e.exceptions[0]
        print(f"[GATE] FAIL: {type(e).__name__}: {e}", flush=True)
        for log in sorted(work.glob("*.log")):
            print(f"--- {log.name} (tail) ---")
            print("\n".join(log.read_text(encoding="utf-8", errors="replace").splitlines()[-15:]))
        return 1
    finally:
        if stack:
            stack.stop()
    print(f"[GATE] PASS: {gate.assertions} assertions, gates (i) and (ii)", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

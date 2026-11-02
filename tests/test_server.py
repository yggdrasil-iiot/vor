"""The configuration file and the MCP surface, through a real MCP client talking to `python -m vor.server` on stdio."""

import asyncio
import json
import os
import sys
from pathlib import Path

from helpers import BINDING, FIXTURES, fixture_now, metric, payload, TOPIC
from vor.server import Vor
from vor.stream import SampleCache


def config(tmp: Path) -> Path:
    cfg = {"registry": str(FIXTURES / "registries" / "active"), "trustedKeys": str(FIXTURES / "trusted-keys.jsonl"),
           "stateDir": "state", "mqtt": "tcp://127.0.0.1:1",
           "questions": {"mixer1-temp": {"stream": "line1", "binding": BINDING,
                                         "description": "Mixer1 process temperature in Cel"}}}
    path = tmp / "vor.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    return path


def test_from_config_answers_the_configured_question(tmp_path):
    cache = SampleCache(clock_ms=lambda: 0)
    vor, cfg = Vor.from_config(config(tmp_path), cache)
    now = fixture_now(FIXTURES / "registries" / "active" / "mappings")
    cache.on_message("spBv1.0/Bifrost:Line1/NBIRTH/recipe-edge", payload(0))
    cache.on_message(TOPIC, payload(1, metric("Temp", 200.0, timestamp=now - 100, server=now - 90)))
    out = vor.read("mixer1-temp", now)
    assert out["verdict"]["usable"] and out["answer"]["sample"]["value"] == 200.0
    assert (tmp_path / "state" / "floors" / "line1.json").exists(), "stateDir resolves against the config file"
    assert cfg["mqtt"] == "tcp://127.0.0.1:1"


def test_mcp_stdio_lists_one_tool_and_refuses_an_unknown_question(tmp_path):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    async def session():
        params = StdioServerParameters(command=sys.executable, args=["-m", "vor.server"],
                                       env={**os.environ, "VOR_CONFIG": str(config(tmp_path))})
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as s:
                await s.initialize()
                tools = (await s.list_tools()).tools
                result = await s.call_tool("read_governed", {"question_id": "free-form ns=2;s=Line1/Mixer1.Temp"})
                return tools, result

    tools, result = asyncio.run(asyncio.wait_for(session(), 60))
    assert [t.name for t in tools] == ["read_governed"]
    assert "mixer1-temp" in tools[0].description
    body = json.loads(result.content[0].text)
    assert body["answer"] is None and body["verdict"]["reason"] == "binding-invalid"
    assert body["verdict"]["evidence"]["rule"] == "question-unknown"

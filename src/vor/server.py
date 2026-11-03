"""The MCP surface: one read-only tool, read_governed(question_id), over stdio.

Configuration is a JSON file named by VOR_CONFIG (paths relative to that file):

    {"registry": "registry", "trustedKeys": "trusted-keys.jsonl", "stateDir": "state",
     "mqtt": "tcp://localhost:1883",
     "questions": {"mixer1-temp": {"stream": "line1", "binding": "vor-binding-mixer1-temp",
                                   "description": "Mixer1 process temperature in Cel"}}}

Each call verifies the registry again from its bytes against the wall clock, so a new head, an expired head or a
retirement is seen at the next call. Only configured question ids are answered: no free-form node, topic or policy.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path

from .head import FloorStore, load_trusted_keys
from .refusal import Refusal
from .release import load
from .stream import MqttFeed, SampleCache
from .verdict import evaluate


@dataclass(frozen=True)
class Question:
    question_id: str
    stream: str
    binding: str
    description: str


class Vor:
    def __init__(self, registry: Path, trusted_keys: Path, state_dir: Path, questions: dict[str, Question],
                 cache: SampleCache):
        self.mappings = registry / "mappings"
        self.trusted_keys = trusted_keys
        self.floors = FloorStore(state_dir)
        self.questions = questions
        self.cache = cache

    @classmethod
    def from_config(cls, path: Path, cache: SampleCache) -> tuple["Vor", dict]:
        cfg = json.loads(path.read_text(encoding="utf-8"))
        base = path.parent
        questions = {qid: Question(qid, q["stream"], q["binding"], q.get("description", ""))
                     for qid, q in cfg["questions"].items()}
        vor = cls(base / cfg["registry"], base / cfg["trustedKeys"], base / cfg["stateDir"], questions, cache)
        return vor, cfg

    def read(self, question_id: str, now_ms: int) -> dict:
        q = self.questions.get(question_id)
        try:
            if q is None:
                raise Refusal("binding-invalid", rule="question-unknown", questionId=question_id,
                              known=sorted(self.questions))
            governed = load(self.mappings, load_trusted_keys(self.trusted_keys), self.floors, now_ms,
                            question_id, q.stream, q.binding)
            b = governed.binding
            # A sample under another device of the edge is evaluated only when the bound device has none, so that
            # data published under the wrong device id is refused location-mismatch rather than no-sample.
            sample = (self.cache.get(b["group"], b["edge"], b["device"], b["metric"])
                      or self.cache.elsewhere(b["group"], b["edge"], b["device"], b["metric"]))
            return evaluate(governed, sample, now_ms)
        except Refusal as r:
            out = r.payload()
            out["verdict"]["evidence"].setdefault("questionId", question_id)
            return out


def main() -> None:
    from mcp.server.fastmcp import FastMCP

    cache = SampleCache()
    vor, cfg = Vor.from_config(Path(os.environ["VOR_CONFIG"]), cache)
    feed = MqttFeed(cfg["mqtt"], cache)
    feed.start()
    listing = "; ".join(f"{q.question_id}: {q.description}" for q in vor.questions.values())
    mcp = FastMCP("vor")

    @mcp.tool(description="Read one governed value by question id, or get a structured refusal. "
                          f"Known questions: {listing}. The answer pins the Bifrost release, head, meaning, unit, "
                          "ISA-95 location, temporal policy and sample; verdict.usable says whether it may be used.")
    def read_governed(question_id: str) -> dict:
        return vor.read(question_id, time.time_ns() // 1_000_000)

    try:
        mcp.run()
    finally:
        feed.stop()


if __name__ == "__main__":
    main()

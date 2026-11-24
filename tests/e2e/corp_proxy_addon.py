"""Stand-in for a TLS-inspecting corporate proxy: records what it can see."""
import json
import os

LOG = open(os.path.join(os.environ["E2E_DIR"], "corp_seen.jsonl"), "a")


def request(flow):
    LOG.write(json.dumps({"host": flow.request.pretty_host, "path": flow.request.path,
                          "body": flow.request.get_text(strict=False) or ""}) + "\n")
    LOG.flush()

#!/usr/bin/env python3
"""Build the IOC Digest site + machine-readable feeds from a data/issue-NNN.json file.

Usage:
    python build.py                 # builds the highest-numbered issue in data/
    python build.py data/issue-001.json

Outputs (under docs/, ready for GitHub Pages):
    docs/index.html                     latest issue (defanged only)
    docs/archive/issue-NNN.html         permanent copy of each issue
    docs/feeds/issue-NNN-iocs.txt       one indicator per line, DEFANGED
    docs/feeds/issue-NNN-iocs.clean.txt refanged copy for TIP/SIEM import (may trip AV)
    docs/feeds/issue-NNN-iocs.csv       full context, defanged + clean columns
    docs/feeds/issue-NNN.stix2.json     STIX 2.1 bundle (hash/domain/ip/url only, clean)

Storage rule: every network indicator in data/*.json is DEFANGED ([.]).
Only feed files marked "clean" ever contain refanged values.
"""

import csv
import html
import json
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).parent
DOCS = ROOT / "docs"

STIX_PATTERNS = {
    "sha256": "[file:hashes.'SHA-256' = '{v}']",
    "domain": "[domain-name:value = '{v}']",
    "ip": "[ipv4-addr:value = '{v}']",
    "url": "[url:value = '{v}']",
}

SEV_LABEL = {"crit": "CRITICAL", "high": "HIGH", "med": "MEDIUM"}


def refang(value: str) -> str:
    return value.replace("[.]", ".")


def esc(value: str) -> str:
    return html.escape(value, quote=True)


def build_incident(inc: dict) -> str:
    rows = []
    for ioc in inc["iocs"]:
        rows.append(
            f'          <tr data-type="{esc(ioc["category"])}">\n'
            f'            <td><span class="t-badge">{esc(ioc["type"])}</span></td>\n'
            f'            <td><button class="val" data-defanged="{esc(ioc["value"])}">{esc(ioc["value"])}</button></td>\n'
            f'            <td class="ctx">{esc(ioc["context"])}</td>\n'
            f'            <td class="seen">{esc(ioc.get("seen", "—"))}</td>\n'
            f"          </tr>"
        )

    facts = "".join(f"\n        <span>{esc(f)}</span>" for f in inc.get("facts", []))
    attack = " · ".join(inc.get("attack", []))
    sources = " · ".join(
        f'<a href="{esc(s["url"])}" rel="noopener">{esc(s["label"])}</a>'
        for s in inc.get("sources", [])
    )
    sev = inc["severity"]
    wide = " wide" if inc.get("wide") else ""

    return f"""  <section class="incident {sev}{wide}">
    <div class="inc-head">
      <div class="inc-lead">
        <div class="inc-title">
          <span class="sev {sev}">{SEV_LABEL[sev]}</span>
          <h2>{inc["title"]}</h2>
        </div>
        <p class="inc-sum">{inc["summary"]}</p>
        <div class="inc-meta">
          <span>FIRST SEEN {esc(inc["first_seen"])}</span>{facts}
          <span class="attck">{attack}</span>
          <span>{sources}</span>
        </div>
      </div>
      <span class="inc-kind">{esc(inc["kind"])}</span>
    </div>
    <div class="act-row">
      <b>ACTION</b>
      <span>{esc(inc["action"])}</span>
      <button class="tbtn copy-inc" data-inc="{esc(inc["id"])}">COPY IOCs</button>
    </div>
    <div class="scroll">
      <table data-inc="{esc(inc["id"])}">
        <thead>
          <tr><th class="w-type">Type</th><th>Indicator</th><th>Context</th><th class="w-seen">Seen</th></tr>
        </thead>
        <tbody>
{chr(10).join(rows)}
        </tbody>
      </table>
    </div>
  </section>"""


def build_feeds(issue: dict, tag: str) -> None:
    feeds = DOCS / "feeds"
    feeds.mkdir(parents=True, exist_ok=True)
    week = issue["week"]

    # --- txt (defanged) and clean.txt ---
    # Feeds are kept ASCII-only for maximum importer portability. ascii() escapes any
    # stray non-ASCII (and makes the RTLO marker visible), so no downstream tool mojibakes.
    def a(s: str) -> str:
        return ascii(s)[1:-1]

    def txt_lines(clean: bool) -> str:
        out = [
            f"# IOC//DIGEST issue {tag} - week of {week}",
            "# " + ("CLEAN values - import into TIP/SIEM. May trip AV/mail scanning."
                    if clean else
                    "DEFANGED values. Refang: replace [.] with .  (sed 's/\\[\\.\\]/./g')"),
        ]
        for inc in issue["incidents"]:
            src = ", ".join(s["url"] for s in inc.get("sources", []))
            out.append(f"#\n# --- {a(inc['title'])}  ({src})")
            for ioc in inc["iocs"]:
                v = refang(ioc["value"]) if clean else ioc["value"]
                out.append(a(v))
        return "\n".join(out) + "\n"

    (feeds / f"issue-{tag}-iocs.txt").write_text(txt_lines(False), encoding="utf-8")
    (feeds / f"issue-{tag}-iocs.clean.txt").write_text(txt_lines(True), encoding="utf-8")

    # --- csv (utf-8-sig so Excel renders context em-dashes instead of mojibake) ---
    with open(feeds / f"issue-{tag}-iocs.csv", "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(["incident", "severity", "kind", "type", "category",
                    "indicator_defanged", "indicator_clean", "context", "seen", "sources"])
        for inc in issue["incidents"]:
            src = " ".join(s["url"] for s in inc.get("sources", []))
            for ioc in inc["iocs"]:
                w.writerow([inc["title"], SEV_LABEL[inc["severity"]], inc["kind"],
                            ioc["type"], ioc["category"], ioc["value"],
                            refang(ioc["value"]), ioc["context"], ioc.get("seen", ""), src])

    # --- STIX 2.1 (patternable types only) ---
    ts = f"{week}T00:00:00.000Z"
    objects, skipped = [], 0
    for inc in issue["incidents"]:
        for ioc in inc["iocs"]:
            tpl = STIX_PATTERNS.get(ioc["type"])
            if not tpl:
                skipped += 1
                continue
            clean = refang(ioc["value"]).replace("\\", "\\\\").replace("'", "\\'")
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": "indicator--" + str(uuid.uuid5(uuid.NAMESPACE_URL, f"ioc-digest/{tag}/{ioc['value']}")),
                "created": ts,
                "modified": ts,
                "name": f"{inc['title']}: {ioc['context']}",
                "description": f"Source: {'; '.join(s['url'] for s in inc.get('sources', []))}",
                "pattern": tpl.format(v=clean),
                "pattern_type": "stix",
                "valid_from": ts,
                "labels": ["malicious-activity"],
            })
    bundle = {
        "type": "bundle",
        "id": "bundle--" + str(uuid.uuid5(uuid.NAMESPACE_URL, f"ioc-digest/bundle/{tag}")),
        "objects": objects,
    }
    (feeds / f"issue-{tag}.stix2.json").write_text(
        json.dumps(bundle, indent=2), encoding="utf-8")
    print(f"  feeds: txt, clean.txt, csv, stix2.json ({len(objects)} STIX indicators, {skipped} non-patternable types in txt/csv only)")


def render_page(issue: dict, template: str, *, feed_prefix: str,
                archive_href: str, archive_label: str) -> str:
    tag = f"{issue['issue']:03d}"
    iocs = [i for inc in issue["incidents"] for i in inc["iocs"]]
    counts = {c: sum(1 for i in iocs if i["category"] == c) for c in ("hash", "net", "host")}
    feeds_html = "\n  ".join(
        f'<a class="file" href="{feed_prefix}{name}">{name}</a>'
        for name in (f"issue-{tag}-iocs.txt", f"issue-{tag}-iocs.clean.txt",
                     f"issue-{tag}-iocs.csv", f"issue-{tag}.stix2.json"))
    return (template
            .replace("{{TITLE}}", f"IOC Digest — Issue {tag} · Week of {issue['week']}")
            .replace("{{ISSUE_META}}",
                     f"ISSUE {tag} · WK {issue['week']} · {len(issue['incidents'])} INCIDENTS · {len(iocs)} IOCs")
            .replace("{{ARCHIVE_HREF}}", archive_href)
            .replace("{{ARCHIVE_LABEL}}", archive_label)
            .replace("{{COUNT_ALL}}", str(len(iocs)))
            .replace("{{COUNT_HASH}}", str(counts["hash"]))
            .replace("{{COUNT_NET}}", str(counts["net"]))
            .replace("{{COUNT_HOST}}", str(counts["host"]))
            .replace("{{INCIDENTS}}", "\n".join(build_incident(i) for i in issue["incidents"]))
            .replace("{{FEEDS}}", feeds_html))


def build_archive_index(issues: list[dict]) -> None:
    """Static archive listing every issue, newest first."""
    cards = []
    for issue in sorted(issues, key=lambda x: x["issue"], reverse=True):
        tag = f"{issue['issue']:03d}"
        n_inc = len(issue["incidents"])
        n_ioc = sum(len(inc["iocs"]) for inc in issue["incidents"])
        titles = " · ".join(esc(inc["title"].split(" — ")[0]) for inc in issue["incidents"][:5])
        if n_inc > 5:
            titles += f" · +{n_inc - 5} more"
        cards.append(
            f'  <a class="issue-card" href="issue-{tag}.html">\n'
            f'    <div class="ic-top"><span class="ic-tag">ISSUE {tag}</span>'
            f'<span class="ic-meta">WK {esc(issue["week"])} · {n_inc} incidents · {n_ioc} IOCs</span></div>\n'
            f'    <p class="ic-titles">{titles}</p>\n'
            f"  </a>"
        )
    template = (ROOT / "templates" / "archive.html").read_text(encoding="utf-8")
    (DOCS / "archive" / "index.html").write_text(
        template.replace("{{CARDS}}", "\n".join(cards)), encoding="utf-8")
    print(f"built archive index: docs/archive/index.html ({len(issues)} issues)")


def build(path: Path) -> None:
    issue = json.loads(path.read_text(encoding="utf-8"))
    tag = f"{issue['issue']:03d}"
    template = (ROOT / "templates" / "page.html").read_text(encoding="utf-8")

    DOCS.mkdir(exist_ok=True)
    (DOCS / "archive").mkdir(exist_ok=True)

    all_issues = [json.loads(p.read_text(encoding="utf-8"))
                  for p in sorted((ROOT / "data").glob("issue-*.json"))]
    latest = max(i["issue"] for i in all_issues)
    is_latest = issue["issue"] == latest

    # index.html always shows the newest issue; a plain issue only writes its archive copy.
    if is_latest:
        page = render_page(issue, template, feed_prefix="feeds/",
                           archive_href="archive/", archive_label="ARCHIVE ▾")
        (DOCS / "index.html").write_text(page, encoding="utf-8")

    archived = render_page(issue, template, feed_prefix="../feeds/",
                           archive_href="index.html", archive_label="← ALL ISSUES")
    (DOCS / "archive" / f"issue-{tag}.html").write_text(archived, encoding="utf-8")
    print(f"built issue {tag}: "
          + ("docs/index.html + " if is_latest else "")
          + f"docs/archive/issue-{tag}.html")
    build_feeds(issue, tag)
    build_archive_index(all_issues)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        targets = [Path(sys.argv[1])]
    else:
        targets = sorted((ROOT / "data").glob("issue-*.json"))
        if not targets:
            sys.exit("no data/issue-*.json found")
    for t in targets:
        build(t)

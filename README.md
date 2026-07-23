# IOC//DIGEST

A weekly, IOC-first threat digest for defenders. Each issue is a single self-contained
HTML page (no dependencies, works offline) plus machine-readable indicator feeds.
Incidents are divided by threat (malware family, CVE, campaign), and every indicator
is click-to-copy, filterable by type, and shown defanged with an in-browser clean toggle.

## Layout

```
data/issue-NNN.json    one issue = one JSON file (the only thing you edit weekly)
templates/page.html    the page template (palettes, layout, JS)
build.py               renders data -> docs/
docs/                  publishable output (GitHub Pages serves this)
  index.html           latest issue
  archive/             every past issue
  feeds/               .txt (defanged), .clean.txt, .csv, .stix2.json
```

## Weekly workflow

1. Copy the previous `data/issue-NNN.json`, bump `issue` and `week`.
2. Fill in 2–4 incidents from cited open sources (CISA, vendor blogs, abuse.ch,
   ANY.RUN, Rapid7, The DFIR Report…). Transcribe indicators **exactly** and link
   every incident to its source.
3. `python build.py`
4. Commit and push — GitHub Pages publishes `docs/` automatically.

## Defang policy (important)

**Every network indicator is stored defanged (`[.]`) — in `data/`, in the HTML, and
in the default feeds.** Clean values exist only:

- in the browser's memory (the copy buttons and the DEFANGED/CLEAN toggle refang on
  the fly), and
- in the explicitly named `*.clean.txt` / `.stix2.json` feeds for TIP/SIEM import.

This is not cosmetic: files containing clean malicious URLs get quarantined by AV
and mail gateways (Windows Defender ate the first draft of this repo's data file).
Defanged-at-rest keeps the repo, the Pages site, and subscribers' downloads safe;
the clean feeds are there for machines, clearly labeled.

## Publishing

- Create a GitHub repo, push, then Settings → Pages → deploy from branch, `/docs` folder.
- Announce each issue anywhere (mail, social) with a link to the page and the feeds —
  never attach the HTML or clean feeds to email.
- STIX bundles cover hash/domain/ip/url indicators; host artifacts (paths, mutexes,
  commands, RTLO filenames) live in the txt/csv feeds only.

## Editorial rules

- Severity reflects risk to a general defender audience, not headline volume.
- The durable signal (task name, beacon pattern, install path) goes in the summary
  bold line; hashes and IPs are expected to rotate.
- One ACTION line per incident: what to block, patch, or hunt — today.
- No actor attribution. Readers defend; they don't need whodunit.
- If an indicator lives on abused legitimate infrastructure (e.g. a Telegraph page),
  say so in its context so nobody blocks the whole service.

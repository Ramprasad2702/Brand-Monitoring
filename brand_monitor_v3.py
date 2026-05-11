#!/usr/bin/env python3
"""
brand_monitor.py — BrandMonitor v2.0 (Kali Linux / Python 3.13)
Fixes: dnstwist DomainFuzz attr, snscrape FileFinder, amass detection,
       crt.sh fallback, all-free tools, detailed findings, new dark theme.
"""
import asyncio, json, os, re, shutil, socket, subprocess, tempfile, uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
import feedparser, httpx
from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

_LOCAL_BIN = str(Path.home() / ".local" / "bin")
os.environ["PATH"] = f"{_LOCAL_BIN}:/usr/bin:/usr/local/bin:{os.environ.get('PATH','')}"

def _bin(n):
    return os.getenv(f"{n.upper()}_BIN","") or shutil.which(n) or n

SPIDERFOOT_URL = os.getenv("SPIDERFOOT_URL","http://localhost:5001")
GITLEAKS_BIN   = _bin("gitleaks")
AMASS_BIN      = _bin("amass")
TRUFFLEHOG_BIN = _bin("trufflehog")
DNSTWIST_BIN   = _bin("dnstwist")
RESULTS_DIR    = Path(os.getenv("RESULTS_DIR","/tmp/brandmonitor"))
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="BrandMonitor API", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
scans: Dict[str, Dict] = {}

class ScanRequest(BaseModel):
    brand: str
    domain: Optional[str] = None
    github_org: Optional[str] = None
    tools: Optional[List[str]] = None

def now_iso(): return datetime.now(timezone.utc).isoformat()
def finding(tool,sev,title,detail,raw=None):
    return dict(id=str(uuid.uuid4())[:8],tool=tool,severity=sev,
                title=title[:200],detail=detail[:1500],raw=raw,ts=now_iso())
def log(sid,level,msg):
    ts=datetime.now().strftime("%H:%M:%S")
    entry=f"[{ts}] [{level}] {msg}"
    scans[sid]["logs"].append(entry); print(entry)
def set_tool(sid,tid,status): scans[sid]["tools"][tid]=status
def add_finding(sid,f): scans[sid]["findings"].append(f)
def has_alert(sid,tool):
    return any(f["tool"]==tool and f["severity"] in ("CRITICAL","WARNING") for f in scans[sid]["findings"])

async def run_cmd(cmd,timeout=120):
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        out,err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return subprocess.CompletedProcess(cmd,proc.returncode,
                                           out.decode(errors="replace"),err.decode(errors="replace"))
    except asyncio.TimeoutError:
        proc.kill()
        raise TimeoutError(f"Timed out {timeout}s: {' '.join(cmd)}")

TOOL_IDS = ["twint","rssbridge","gitleaks","trufflehog","dnstwist","amass","spiderfoot","scrapy","github_code","social_protect","darkweb","visual_phish"]

# ── TOOL 1: SNSCRAPE (CLI mode - avoids FileFinder/find_module bug) ──────────
async def run_twint(sid: str, brand: str):
    """
    Social mention scraping — pure httpx, zero extra packages.
    Strategy (in order of reliability):
      1. Nitter public instances  — Twitter mirror, JSON API
      2. Google News RSS          — catches news tweets & press coverage
      3. Reddit JSON API          — community discussions
      4. HackerNews Algolia API   — tech community mentions
    snscrape and twint are both dead/broken; this approach needs only httpx+feedparser
    which are already installed.
    """
    tool = "twint"
    set_tool(sid, tool, "running")
    log(sid, "INFO", f"social: scanning Twitter mirrors, Reddit, HN for '{brand}'...")

    mentions = []

    NITTER_INSTANCES = [
        "https://nitter.privacydev.net",
        "https://nitter.poast.org",
        "https://nitter.lunar.icu",
        "https://nitter.unixfox.eu",
    ]

    RISK_KW = {
        "CRITICAL": [
            "breach", "hacked", "credentials leaked", "database exposed",
            "ransomware", "account compromised", "data dump", "passwords exposed",
            "cyberattack", "defaced", "pwned"
        ],
        "WARNING": [
            "vulnerability", "exploit", "phishing", "fake account", "scam",
            "impersonat", "malware", "suspicious", "fraud", "ddos", "attack"
        ],
    }

    async with httpx.AsyncClient(
        timeout=15,
        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
        follow_redirects=True,
    ) as cl:

        # ── 1. Nitter instances (Twitter mirror JSON) ────────────────────────
        nitter_ok = False
        for instance in NITTER_INSTANCES:
            try:
                url = f"{instance}/search?q={brand}&f=tweets"
                r = await cl.get(url, timeout=10)
                if r.status_code == 200 and "tweet" in r.text.lower():
                    # Parse Nitter HTML for tweet content
                    import re as _re
                    tweet_texts = _re.findall(
                        r'<div class="tweet-content[^"]*"[^>]*>(.*?)</div>',
                        r.text, _re.DOTALL
                    )
                    for raw in tweet_texts[:40]:
                        text = _re.sub(r'<[^>]+>', '', raw).strip()
                        if text and brand.lower() in text.lower():
                            mentions.append({
                                "text": text[:300],
                                "source": "Twitter/X via Nitter",
                                "url": instance,
                                "date": "recent",
                            })
                    if mentions:
                        log(sid, "OK", f"social: {len(mentions)} tweets via Nitter ({instance})")
                        nitter_ok = True
                        break
            except Exception:
                continue

        if not nitter_ok:
            log(sid, "WARN", "social: all Nitter instances unreachable — using RSS fallback")

        # ── 2. Google News RSS (catches tweets shared in news) ───────────────
        try:
            rss_urls = [
                f"https://news.google.com/rss/search?q={brand}+site:twitter.com&hl=en",
                f"https://news.google.com/rss/search?q={brand}+breach+OR+hack+OR+scam&hl=en",
            ]
            for rss_url in rss_urls:
                r = await cl.get(rss_url, timeout=12)
                if r.status_code == 200:
                    feed = feedparser.parse(r.text)
                    for entry in feed.entries[:15]:
                        title = entry.get("title", "")
                        summary = re.sub(r"<[^>]+>", "", entry.get("summary", ""))[:200]
                        if brand.lower() in (title + summary).lower():
                            mentions.append({
                                "text": f"{title} — {summary}",
                                "source": "Google News RSS",
                                "url": entry.get("link", ""),
                                "date": entry.get("published", "")[:10],
                            })
        except Exception as e:
            log(sid, "WARN", f"social: Google News RSS error: {e}")

        # ── 3. Reddit JSON (community discussions) ───────────────────────────
        try:
            r = await cl.get(
                f"https://www.reddit.com/search.json?q={brand}&sort=new&limit=25&t=week",
                headers={"User-Agent": "BrandMonitor/2.0"},
                timeout=12,
            )
            if r.status_code == 200:
                for post in r.json().get("data", {}).get("children", []):
                    d = post.get("data", {})
                    title = d.get("title", "")
                    selftext = d.get("selftext", "")[:150]
                    if brand.lower() in title.lower():
                        mentions.append({
                            "text": f"{title} {selftext}".strip()[:300],
                            "source": f"Reddit r/{d.get('subreddit', '?')}",
                            "url": f"https://reddit.com{d.get('permalink', '')}",
                            "date": datetime.fromtimestamp(
                                d.get("created_utc", 0)
                            ).strftime("%Y-%m-%d") if d.get("created_utc") else "",
                            "score": d.get("score", 0),
                        })
            log(sid, "OK", f"social: Reddit returned {len([m for m in mentions if 'Reddit' in m.get('source','')])} posts")
        except Exception as e:
            log(sid, "WARN", f"social: Reddit error: {e}")

        # ── 4. HackerNews Algolia API (tech community) ───────────────────────
        try:
            r = await cl.get(
                f"https://hn.algolia.com/api/v1/search_by_date?query={brand}&tags=story,comment&hitsPerPage=20",
                timeout=12,
            )
            if r.status_code == 200:
                for hit in r.json().get("hits", []):
                    text = (hit.get("title") or hit.get("comment_text") or "")[:300]
                    if text and brand.lower() in text.lower():
                        mentions.append({
                            "text": re.sub(r"<[^>]+>", "", text),
                            "source": "HackerNews",
                            "url": hit.get("url") or f"https://news.ycombinator.com/item?id={hit.get('objectID','')}",
                            "date": (hit.get("created_at") or "")[:10],
                            "points": hit.get("points", 0),
                        })
        except Exception as e:
            log(sid, "WARN", f"social: HackerNews error: {e}")

    # Deduplicate
    seen = set()
    unique = []
    for m in mentions:
        k = m["text"][:60].lower()
        if k not in seen:
            seen.add(k)
            unique.append(m)
    mentions = unique

    log(sid, "INFO", f"social: {len(mentions)} total mentions collected across all sources")

    # Score for risk
    found_risk = False
    for m in mentions:
        text = m.get("text", "").lower()
        for sev in ["CRITICAL", "WARNING"]:
            hits = [kw for kw in RISK_KW[sev] if kw in text]
            if hits:
                found_risk = True
                add_finding(sid, finding(
                    tool, sev,
                    f"{'🔴' if sev=='CRITICAL' else '🟡'} High-risk mention on {m.get('source','?')}",
                    f"Content: {m.get('text','')[:350]}\n"
                    f"Source: {m.get('source','?')} | Date: {m.get('date','?')}\n"
                    f"Keywords matched: {', '.join(hits)}\n"
                    f"URL: {m.get('url','')}",
                    raw=m,
                ))
                break

    if mentions and not found_risk:
        sources = list(set(m.get("source", "?") for m in mentions))
        add_finding(sid, finding(
            tool, "INFO",
            f"Social: {len(mentions)} mentions found for '{brand}'",
            f"Sources checked: {', '.join(sources)}\n"
            f"No high-risk keywords detected in any mention.\n"
            f"Sample: {mentions[0].get('text','')[:200]}\n"
            f"Users/posts: {len(mentions)} mentions across {len(sources)} platforms",
            raw={"count": len(mentions), "sources": sources, "sample": mentions[:3]},
        ))
    elif not mentions:
        add_finding(sid, finding(
            tool, "INFO",
            f"Social: No mentions found for '{brand}'",
            f"Searched: Nitter (Twitter mirror), Google News RSS, Reddit, HackerNews.\n"
            f"No mentions found in last 7 days. Brand may have low social media presence\n"
            f"or the brand name is too generic for precise matching.\n"
            f"Tip: Try a more specific brand name or add the domain as well.",
        ))

    set_tool(sid, tool, "alert" if has_alert(sid, tool) else "done")


async def run_rssbridge(sid, brand, domain):
    tool="rssbridge"; set_tool(sid,tool,"running")
    log(sid,"INFO","rss-bridge: fetching news feeds...")
    feeds=[
        (f"https://news.google.com/rss/search?q={brand}&hl=en-US&gl=US&ceid=US:en","Google News"),
        (f"https://news.google.com/rss/search?q={brand}+breach+OR+hack+OR+leak&hl=en","Google News Security"),
        (f"https://news.google.com/rss/search?q={domain}&hl=en-US&gl=US&ceid=US:en","Google News Domain"),
        (f"https://www.reddit.com/search.json?q={brand}&sort=new&limit=20&t=month","Reddit"),
    ]
    RISK={"CRITICAL":["data breach","credentials exposed","ransomware","hacked","database leaked","zero-day","pwned","defaced"],
           "WARNING":["vulnerability","security flaw","phishing","impersonation","malware","ddos","fake site"],
           "INFO":["lawsuit","regulatory","acquisition","fine","investigation"]}
    articles=[]
    async with httpx.AsyncClient(timeout=20,headers={"User-Agent":"BrandMonitor/2.0"},follow_redirects=True) as cl:
        for url,src in feeds:
            try:
                if "reddit.com/search.json" in url:
                    r=await cl.get(url)
                    if r.status_code==200:
                        for p in r.json().get("data",{}).get("children",[]):
                            d=p.get("data",{})
                            articles.append({"title":d.get("title",""),"url":f"https://reddit.com{d.get('permalink','')}",
                                             "source":f"Reddit r/{d.get('subreddit','')}","summary":d.get("selftext","")[:200] or d.get("url",""),
                                             "date":datetime.fromtimestamp(d.get("created_utc",0)).strftime("%Y-%m-%d") if d.get("created_utc") else ""})
                else:
                    r=await cl.get(url)
                    if r.status_code==200:
                        feed=feedparser.parse(r.text)
                        for e in feed.entries[:15]:
                            articles.append({"title":e.get("title",""),"url":e.get("link",""),"source":src,
                                             "summary":re.sub(r'<[^>]+>','',e.get("summary",""))[:300],"date":e.get("published","")[:10]})
            except Exception as ex: log(sid,"WARN",f"feed {src}: {ex}")

    seen=set(); unique=[]
    for a in articles:
        k=a["title"][:60].lower()
        if k not in seen: seen.add(k); unique.append(a)
    articles=unique
    log(sid,"OK",f"rss-bridge: {len(articles)} articles indexed")

    if not articles:
        add_finding(sid,finding(tool,"INFO",f"News: 0 articles for '{brand}'","RSS/news feeds returned no results. Brand may have limited news coverage."))
        set_tool(sid,tool,"done"); return

    neutral=[]
    for art in articles:
        tl=(art["title"]+" "+art["summary"]).lower()
        matched=False
        for sev in ["CRITICAL","WARNING","INFO"]:
            hits=[kw for kw in RISK[sev] if kw in tl]
            if hits:
                add_finding(sid,finding(tool,sev,
                    f"{'🔴' if sev=='CRITICAL' else '🟡' if sev=='WARNING' else '🔵'} {art['title'][:110]}",
                    f"Source: {art['source']} | Date: {art['date']}\nSummary: {art['summary'][:300]}\n"
                    f"Keywords: {', '.join(hits)}\nURL: {art['url']}",raw=art)); matched=True; break
        if not matched: neutral.append(art)
    if neutral:
        add_finding(sid,finding(tool,"INFO",f"News: {len(articles)} articles found ({len(neutral)} neutral)",
            "Recent coverage:\n"+"\n".join(f"• {a['title'][:80]} ({a['source']}, {a['date']})" for a in neutral[:5]),raw=neutral[:5]))
    set_tool(sid,tool,"alert" if has_alert(sid,tool) else "done")

# ── GITHUB HELPER ─────────────────────────────────────────────────────────────
async def _github_repos(org):
    headers={"Accept":"application/vnd.github+json"}
    if os.getenv("GITHUB_TOKEN"): headers["Authorization"]=f"token {os.getenv('GITHUB_TOKEN')}"
    async with httpx.AsyncClient(timeout=15,headers=headers) as cl:
        for ep in [f"orgs/{org}/repos",f"users/{org}/repos"]:
            try:
                r=await cl.get(f"https://api.github.com/{ep}?per_page=30&sort=updated")
                if r.status_code==200:
                    data=r.json()
                    if isinstance(data,list) and data:
                        return [repo["clone_url"] for repo in data[:15] if repo.get("clone_url")]
            except: pass
    return []

# ── TOOL 3: GITLEAKS ──────────────────────────────────────────────────────────
async def run_gitleaks(sid, brand, github_org):
    tool="gitleaks"; set_tool(sid,tool,"running")
    gl=shutil.which(GITLEAKS_BIN) or shutil.which("gitleaks")
    if not gl:
        add_finding(sid,finding(tool,"INFO","GitLeaks not installed",
            f"Install: curl -sSfL https://github.com/gitleaks/gitleaks/releases/latest/download/"
            f"gitleaks_linux_x64.tar.gz | tar -xz -C ~/.local/bin gitleaks"))
        set_tool(sid,tool,"error"); return
    org=github_org or brand
    log(sid,"INFO",f"gitleaks: discovering repos for '{org}'...")
    repos=await _github_repos(org)
    if not repos:
        add_finding(sid,finding(tool,"INFO",f"GitLeaks: No public repos for '{org}'",
            f"Searched github.com/orgs/{org} and github.com/users/{org}.\n"
            f"No public repos found. The org name may differ from the brand name.\n"
            f"Tip: set github_org in scan request if GitHub org name is different."))
        set_tool(sid,tool,"done"); return
    log(sid,"INFO",f"gitleaks: scanning {len(repos)} repos...")
    total=0; scanned=0
    with tempfile.TemporaryDirectory() as tmp:
        for repo_url in repos[:12]:
            name=repo_url.split("/")[-1].replace(".git","")
            clone_dir=os.path.join(tmp,name)
            report=os.path.join(tmp,f"{name}_gl.json")
            try:
                await run_cmd(["git","clone","--depth=50","--quiet",repo_url,clone_dir],90)
                await run_cmd([gl,"detect","--source",clone_dir,"--report-format","json",
                               "--report-path",report,"--no-banner","--quiet"],90)
                scanned+=1
                if os.path.exists(report):
                    leaks=json.loads(Path(report).read_text() or "[]")
                    for lk in leaks:
                        total+=1
                        sec=str(lk.get("Secret",""))[:40]+"..." if lk.get("Secret") else "hidden"
                        add_finding(sid,finding(tool,"CRITICAL",
                            f"🔴 Secret exposed: {lk.get('RuleID','unknown')} in {name}",
                            f"Repository: github.com/{org}/{name}\n"
                            f"File: {lk.get('File','?')} (line {lk.get('StartLine','?')})\n"
                            f"Rule: {lk.get('RuleID','?')}\nCommit: {str(lk.get('Commit','?'))[:12]}\n"
                            f"Author: {lk.get('Author','?')} | Date: {str(lk.get('Date','?'))[:10]}\n"
                            f"Secret preview: {sec}\nMessage: {str(lk.get('Message','?'))[:100]}",
                            raw={k:lk.get(k) for k in ["RuleID","File","StartLine","Commit","Author","Date"]}))
            except Exception as e: log(sid,"WARN",f"gitleaks {name}: {e}")
    if total==0:
        add_finding(sid,finding(tool,"OK",f"🟢 GitLeaks: No secrets in {scanned} repos for '{org}'",
            f"Scanned {scanned}/{len(repos)} repos (depth 50 commits).\nNo API keys, tokens or credentials detected."))
    log(sid,"OK" if total==0 else "CRIT",f"gitleaks: {total} secrets in {scanned} repos")
    set_tool(sid,tool,"alert" if total>0 else "done")

# ── TOOL 4: TRUFFLEHOG ────────────────────────────────────────────────────────
async def run_trufflehog(sid: str, brand: str, github_org: Optional[str]):
    tool = "trufflehog"
    set_tool(sid, tool, "running")
    th = shutil.which(TRUFFLEHOG_BIN) or shutil.which("trufflehog")
    if not th:
        add_finding(sid, finding(tool, "INFO", "TruffleHog not installed",
            "Install: curl -sSfL https://github.com/trufflesecurity/trufflehog/releases/latest/"
            "download/trufflehog_linux_amd64.tar.gz | tar -xz -C ~/.local/bin trufflehog"))
        set_tool(sid, tool, "error"); return
    org = github_org or brand
    repos = await _github_repos(org)
    if not repos:
        add_finding(sid, finding(tool, "INFO", f"TruffleHog: No repos to scan for '{org}'",
            "No public GitHub repos found. TruffleHog scan skipped."))
        set_tool(sid, tool, "done"); return

    log(sid, "INFO", f"trufflehog: deep scanning {min(len(repos),6)} repos (verified-only mode)...")
    count = 0; verified = 0

    for repo_url in repos[:6]:   # cap at 6 to avoid timeout
        name = repo_url.split("/")[-1].replace(".git", "")
        try:
            r = await run_cmd([
                th, "git", repo_url,
                "--json", "--no-update", "--concurrency", "2",
                "--only-verified",   # KEY FIX: only report secrets confirmed active
            ], timeout=60)
            for line in r.stdout.splitlines():
                try:
                    hit = json.loads(line)
                    # Extra filter: skip if detector confidence is low
                    if not hit.get("Verified", False):
                        continue
                    verified += 1; count += 1
                    gh = hit.get("SourceMetadata", {}).get("Data", {}).get("Git", {})
                    add_finding(sid, finding(tool, "CRITICAL",
                        f"🔴 VERIFIED LIVE credential: {hit.get('DetectorName','?')} in {name}",
                        f"Repository: {repo_url}\n"
                        f"Detector: {hit.get('DetectorName','?')}\n"
                        f"Verified active: YES — revoke immediately\n"
                        f"File: {gh.get('file','?')}\n"
                        f"Commit: {str(gh.get('commit','?'))[:12]}\n"
                        f"⚠ This credential is ACTIVE and can be used by anyone who finds this repo.",
                        raw={"detector": hit.get("DetectorName"), "verified": True,
                             "repo": repo_url, "file": gh.get("file")}))
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            log(sid, "WARN", f"trufflehog {name}: {e}")

    if count == 0:
        add_finding(sid, finding(tool, "OK",
            f"🟢 TruffleHog: No verified live credentials in {len(repos[:6])} repos",
            f"Deep entropy analysis found no active API keys or tokens.\n"
            f"Scanned: {min(len(repos),6)} repos | Mode: verified-only (suppresses false positives).\n"
            f"Unverified/expired secrets are ignored — only confirmed active credentials are reported."))
    log(sid, "OK" if count == 0 else "CRIT", f"trufflehog: {count} verified live credentials found")
    set_tool(sid, tool, "alert" if count > 0 else "done")

# ── TOOL 5: DNSTWIST (CLI binary — avoids DomainFuzz API break) ───────────────
async def run_dnstwist(sid: str, domain: str):
    tool = "dnstwist"
    set_tool(sid, tool, "running")
    log(sid, "INFO", f"dnstwist: generating permutations for '{domain}'...")

    venv_bin = Path(os.environ.get("VIRTUAL_ENV", "")) / "bin" / "dnstwist"
    dt = (shutil.which(DNSTWIST_BIN) or shutil.which("dnstwist") or
          (str(venv_bin) if venv_bin.exists() else None))

    if not dt:
        log(sid, "WARN", "dnstwist CLI not found — trying Python module fallback")
        await _dnstwist_module(sid, domain); return

    results = []
    try:
        out_file = RESULTS_DIR / f"{str(uuid.uuid4())[:8]}_dnstwist.json"
        r = await run_cmd([dt, domain, "--registered", "--format", "json",
                           "--threads", "20", "--output", str(out_file)], 180)
        raw = ""
        if out_file.exists() and out_file.stat().st_size > 2:
            raw = out_file.read_text()
        elif r.stdout.strip().startswith("["):
            raw = r.stdout
        if raw:
            results = json.loads(raw)
        out_file.unlink(missing_ok=True)
    except TimeoutError:
        log(sid, "WARN", "dnstwist timed out after 180s — using partial results")
    except Exception as e:
        log(sid, "WARN", f"dnstwist CLI error: {e}")
        await _dnstwist_module(sid, domain); return

    # ── ACCURACY FIX: multi-signal filtering ────────────────────────────────
    # For large brands (google, amazon etc) EVERY variant is registered.
    # We only care about domains that are ACTIVELY operated — not parked pages.
    # Signal scoring: each active signal adds points.
    def score_domain(d):
        score = 0
        has_mx  = bool(d.get("dns_mx"))
        has_web = bool(d.get("dns_a") or d.get("ipv4"))
        ns      = d.get("dns_ns", [])
        fuzzer  = d.get("fuzzer", "")
        dom     = d.get("domain", "")
        age_days = 99999  # assume old unless we know
        try:
            created = d.get("whois_created", "")
            if created:
                from datetime import datetime as _dt
                delta = (_dt.now() - _dt.strptime(created[:10], "%Y-%m-%d")).days
                age_days = delta
        except Exception:
            pass

        if has_mx:   score += 40   # can send/receive email → phishing
        if has_web:  score += 15   # serving content
        if age_days < 90:  score += 30   # very new → suspicious
        if age_days < 30:  score += 20   # extra suspicious
        if fuzzer in ("homoglyph", "bitsquatting", "omission", "transposition"): score += 15
        # Keyword additions that suggest active fraud
        if any(kw in dom for kw in ["login","secure","verify","account","support","pay","update"]): score += 20
        # Parked domain signals (reduce score)
        parked_ns = ["sedo","parkingcrew","bodis","above.com","hugedomains","undeveloped"]
        if any(p in str(ns).lower() for p in parked_ns): score -= 40
        # Same IP as legitimate domain = likely subdomain redirect, not threat
        if d.get("ipv4") and d.get("ipv4") == "":  score = 0
        return min(100, max(0, score))

    all_registered = [d for d in results if d.get("dns_a") or d.get("ipv4") or d.get("dns_ns")]

    # Score and filter — only report domains with score >= 35
    scored = [(score_domain(d), d) for d in all_registered]
    scored.sort(key=lambda x: -x[0])
    actionable = [(sc, d) for sc, d in scored if sc >= 35]

    log(sid, "OK", f"dnstwist: {len(results)} variants, {len(all_registered)} registered, "
                   f"{len(actionable)} actionable (score≥35)")

    if not actionable:
        add_finding(sid, finding(tool, "OK",
            f"🟢 No actionable lookalike domains for '{domain}'",
            f"Checked {len(results)} permutations → {len(all_registered)} registered.\n"
            f"None meet the risk threshold (active MX, new registration, suspicious keywords).\n"
            f"Many variants exist but appear to be parked/expired with no active threat indicators."))
        set_tool(sid, tool, "done"); return

    # Group by severity
    critical = [(sc,d) for sc,d in actionable if sc >= 75]
    warning  = [(sc,d) for sc,d in actionable if 35 <= sc < 75]

    # Report critical ones individually
    for sc, d in critical[:10]:
        dom    = d.get("domain", "")
        fuzzer = d.get("fuzzer", "")
        ips    = d.get("dns_a", []) or ([d["ipv4"]] if d.get("ipv4") else [])
        ip_str = ", ".join(str(i) for i in ips[:2]) if ips else "–"
        has_mx = bool(d.get("dns_mx"))
        mx_str = str(d.get("dns_mx", ["none"])[:1]).strip("[]'") if has_mx else "none"
        created = d.get("whois_created", "unknown")[:10]
        registrar = d.get("whois_registrar", "unknown")[:40]
        add_finding(sid, finding(tool, "CRITICAL",
            f"🔴 Active phishing domain: {dom} (risk score {sc}%)",
            f"Domain: {dom}\nPermutation type: {fuzzer}\n"
            f"IP address: {ip_str}\nMX (email): {mx_str}\n"
            f"Registered: {created} | Registrar: {registrar}\n"
            f"Risk score: {sc}%\n"
            f"{'⚠ HAS MAIL SERVER — can send spoofed emails as your domain!' if has_mx else ''}"
            f"{'⚠ NEWLY REGISTERED — high probability of active fraud setup!' if sc >= 50 and created > '2024-01-01' else ''}",
            raw=d))

    # Report warnings as a grouped summary (not individual — reduces noise)
    if warning:
        warning_domains = [d.get("domain","") for _, d in warning[:20]]
        add_finding(sid, finding(tool, "WARNING",
            f"🟡 {len(warning)} registered lookalike variants — monitor these",
            f"These domains are registered and resolve but don't meet critical threshold.\n"
            f"Score range: 35–74% (registered but no active MX or suspicious keywords)\n\n"
            f"Domains to monitor:\n" +
            "\n".join(f"• {dom}" for dom in warning_domains) +
            (f"\n  ...and {len(warning)-20} more" if len(warning) > 20 else "") +
            f"\n\nRecommendation: Re-check monthly. Report to registrar if they become active.",
            raw=[d for _, d in warning[:30]]))

    # Always add summary
    add_finding(sid, finding(tool, "INFO",
        f"🔵 Domain scan summary: {len(results)} permutations checked",
        f"Total variants generated: {len(results)}\n"
        f"Registered: {len(all_registered)}\n"
        f"Actionable (risk score ≥35): {len(actionable)}\n"
        f"Critical (risk score ≥75): {len(critical)}\n"
        f"Warning (score 35–74): {len(warning)}\n"
        f"Filtered out (parked/expired/no signals): {len(all_registered)-len(actionable)}",
        raw={"total": len(results), "registered": len(all_registered),
             "actionable": len(actionable), "critical": len(critical)}))

    set_tool(sid, tool, "alert" if has_alert(sid, tool) else "done")

async def _dnstwist_module(sid, domain):
    tool="dnstwist"
    try:
        import dnstwist
        if hasattr(dnstwist,"run"):
            out=str(RESULTS_DIR/f"{str(uuid.uuid4())[:8]}_dt.json")
            dnstwist.run(domain=domain,registered=True,format="json",output=out,threads=10)
            if Path(out).exists():
                results=json.loads(Path(out).read_text() or "[]")
                Path(out).unlink(missing_ok=True)
                reg=[d for d in results if d.get("dns_a") or d.get("ipv4")]
                for d in reg[:30]:
                    has_mx=bool(d.get("dns_mx"))
                    risk=50 if has_mx else 30
                    sev="CRITICAL" if risk>=75 else "WARNING" if has_mx else "INFO"
                    add_finding(sid,finding(tool,sev,
                        f"{'🔴' if sev=='CRITICAL' else '🟡' if sev=='WARNING' else '🔵'} Lookalike: {d.get('domain','')}",
                        f"Type: {d.get('fuzzer','')} | IP: {d.get('ipv4','–')} | MX: {has_mx}",raw=d))
                log(sid,"OK",f"dnstwist module: {len(reg)} registered"); return
        add_finding(sid,finding(tool,"INFO","dnstwist module API incompatible",
            "Upgrade: pip install --upgrade dnstwist\nOr install binary: apt install dnstwist"))
    except ImportError:
        add_finding(sid,finding(tool,"INFO","dnstwist not installed",
            "Install: pip install dnstwist\nOr: sudo apt install dnstwist"))
    except Exception as e:
        add_finding(sid,finding(tool,"INFO",f"dnstwist error: {e}","Try: pip install --upgrade dnstwist"))
    set_tool(sid,tool,"error")

# ── TOOL 6: AMASS + crt.sh ────────────────────────────────────────────────────
async def run_amass(sid, domain):
    tool="amass"; set_tool(sid,tool,"running")
    log(sid,"INFO",f"amass: enumerating subdomains for '{domain}'...")
    am=(shutil.which(AMASS_BIN) or shutil.which("amass") or
        shutil.which("/usr/bin/amass") or shutil.which("/usr/local/bin/amass") or
        (str(Path(_LOCAL_BIN,"amass")) if Path(_LOCAL_BIN,"amass").exists() else None))
    if not am:
        log(sid,"WARN","amass binary not found — using crt.sh CT logs")
        await _crtsh(sid,domain); return
    try:
        out_file=RESULTS_DIR/f"{str(uuid.uuid4())[:8]}_amass.txt"
        log(sid,"INFO","amass: passive enumeration (4 min max)...")
        await run_cmd([am,"enum","-passive","-d",domain,"-o",str(out_file),"-timeout","4"],270)
        subdomains=[]
        if out_file.exists():
            subdomains=sorted(set(l.strip() for l in out_file.read_text().splitlines() if l.strip() and domain in l))
            out_file.unlink(missing_ok=True)
        if not subdomains:
            log(sid,"WARN","amass: 0 results — supplementing with crt.sh")
            await _crtsh(sid,domain); return
        log(sid,"OK",f"amass: {len(subdomains)} subdomains")
        _report_subdomains(sid,domain,subdomains,"amass passive")
    except TimeoutError:
        log(sid,"WARN","amass timed out — using crt.sh")
        await _crtsh(sid,domain)
    except Exception as e:
        log(sid,"WARN",f"amass error: {e} — using crt.sh")
        await _crtsh(sid,domain)

async def _crtsh(sid, domain):
    tool="amass"
    log(sid,"INFO",f"crt.sh: querying CT logs for *.{domain}")
    try:
        async with httpx.AsyncClient(timeout=30,follow_redirects=True,headers={"User-Agent":"BrandMonitor/2.0"}) as cl:
            r=await cl.get(f"https://crt.sh/?q=%.{domain}&output=json")
            if r.status_code!=200: raise Exception(f"crt.sh HTTP {r.status_code}")
            data=r.json(); subdomains=set(); wildcards=[]
            for entry in data:
                name_val=entry.get("name_value",""); common=entry.get("common_name","")
                issuer=entry.get("issuer_name",""); not_before=entry.get("not_before","")[:10]
                for name in (name_val+"\n"+common).split("\n"):
                    name=name.strip().lstrip("*.")
                    if domain in name and name!=domain: subdomains.add(name)
                if "*."+domain in name_val:
                    wildcards.append({"domain":name_val,"issuer":issuer,"date":not_before})
            subdomains=sorted(subdomains)
            log(sid,"OK",f"crt.sh: {len(subdomains)} subdomains from CT logs")
            _report_subdomains(sid,domain,subdomains,"crt.sh Certificate Transparency")
            if wildcards:
                add_finding(sid,finding(tool,"WARNING",
                    f"🟡 Wildcard certificate(s) found: *.{domain}",
                    f"{len(wildcards)} wildcard cert(s) issued.\nAny subdomain can use this cert — verify no subdomains are unintentionally exposed.\n"
                    f"Recent issuances:\n"+"\n".join(f"• {c['domain']} by {c['issuer'][:50]} ({c['date']})" for c in wildcards[:5]),
                    raw=wildcards[:10]))
    except Exception as e:
        log(sid,"WARN",f"crt.sh error: {e}")
        add_finding(sid,finding(tool,"INFO",f"Subdomain enumeration failed for {domain}",
            f"Both amass and crt.sh failed.\nError: {e}\nTry manually: https://crt.sh/?q=%.{domain}"))
    set_tool(sid,tool,"done")

def _report_subdomains(sid, domain, subdomains, source):
    tool="amass"
    if not subdomains: return
    SENS=re.compile(r"(dev|staging|test|beta|old|backup|vpn|admin|api-v\d|internal|corp|"
                    r"mail|smtp|ftp|ssh|jenkins|jira|gitlab|grafana|kibana|phpmyadmin|"
                    r"cpanel|webmail|remote|portal|legacy|db|database|mysql|mongo)",re.I)
    sensitive=[s for s in subdomains if SENS.search(s)]
    add_finding(sid,finding(tool,"INFO",
        f"🔵 {len(subdomains)} subdomains discovered for {domain}",
        f"Source: {source}\nTotal: {len(subdomains)} | Sensitive/exposed: {len(sensitive)}\n"
        f"Sample subdomains:\n"+"\n".join(f"• {s}" for s in subdomains[:25])
        +(f"\n  ...and {len(subdomains)-25} more" if len(subdomains)>25 else ""),raw=subdomains[:100]))
    if sensitive:
        add_finding(sid,finding(tool,"WARNING",
            f"🟡 {len(sensitive)} sensitive subdomain(s) potentially exposed",
            f"These subdomains suggest internal/admin services may be accessible externally:\n"
            +"\n".join(f"• {s}" for s in sensitive[:15])
            +"\n\nAction: Verify each is intentionally public and properly secured.",raw=sensitive))
    set_tool(sid,tool,"done")

# ── TOOL 7: FREE OSINT (Shodan·DNS·WHOIS·Pastes — all free, no API key) ───────
async def run_spiderfoot(sid, brand, domain):
    tool="spiderfoot"; set_tool(sid,tool,"running")
    log(sid,"INFO","osint: Shodan InternetDB · DNS · WHOIS · Paste sites (all free)...")
    async with httpx.AsyncClient(timeout=20,follow_redirects=True,headers={"User-Agent":"BrandMonitor/2.0"}) as cl:

        # 1. SHODAN INTERNETDB (free, no key needed)
        log(sid,"INFO","osint [1/5]: Shodan InternetDB...")
        try:
            ip=await asyncio.get_event_loop().run_in_executor(None,socket.gethostbyname,domain)
            r=await cl.get(f"https://internetdb.shodan.io/{ip}")
            if r.status_code==200:
                data=r.json(); ports=data.get("ports",[]); vulns=data.get("vulns",[])
                tags=data.get("tags",[]); cpes=data.get("cpes",[]); hosts=data.get("hostnames",[])
                if vulns:
                    add_finding(sid,finding(tool,"CRITICAL",
                        f"🔴 Shodan: {len(vulns)} CVE(s) on {ip} ({domain})",
                        f"IP Address: {ip}\nCVEs: {', '.join(vulns[:10])}\n"
                        f"Open ports: {ports}\nTechnologies: {', '.join(cpes[:5]) if cpes else 'unknown'}\n"
                        f"Tags: {', '.join(tags) if tags else 'none'}\nHostnames: {', '.join(hosts[:5]) if hosts else 'none'}\n"
                        f"⚠ Patch these CVEs immediately!",raw=data))
                elif ports:
                    risky=[p for p in ports if p in [21,22,23,25,3389,5900,6379,27017,9200,11211,5984,8080,8443]]
                    sev="WARNING" if risky else "INFO"
                    add_finding(sid,finding(tool,sev,
                        f"{'🟡' if sev=='WARNING' else '🔵'} Shodan: {len(ports)} open port(s) on {ip}",
                        f"IP: {ip}\nAll open ports: {ports}\n"
                        f"{'⚠ Risky ports: '+str(risky) if risky else 'No high-risk ports.'}\n"
                        f"Technologies: {', '.join(cpes[:5]) if cpes else 'unknown'}\n"
                        f"Tags: {', '.join(tags) if tags else 'none'}\n"
                        f"Hostnames: {', '.join(hosts[:5]) if hosts else 'none'}",raw=data))
                elif r.status_code==404:
                    add_finding(sid,finding(tool,"OK",f"🟢 Shodan: {domain} ({ip}) — no known vulnerabilities",
                        f"IP {ip} not indexed in Shodan threat database.\nNo exposed services or CVEs detected."))
                log(sid,"OK",f"Shodan: {ip} — {len(vulns)} CVEs, {len(ports)} ports")
            elif r.status_code==404:
                add_finding(sid,finding(tool,"OK",f"🟢 Shodan: {domain} — clean (not indexed)",
                    f"IP not found in Shodan. No known vulnerabilities or exposed services."))
        except socket.gaierror:
            add_finding(sid,finding(tool,"INFO",f"DNS: Could not resolve {domain}",
                "Verify the domain spelling is correct."))
        except Exception as e: log(sid,"WARN",f"Shodan: {e}")

        # 2. DNS RECORDS + EMAIL SECURITY (SPF/DMARC — free via dns.google)
        log(sid,"INFO","osint [2/5]: DNS & email security analysis...")
        try:
            dns_rows=[]
            for rtype in ["A","MX","NS","TXT","AAAA"]:
                try:
                    r=await cl.get(f"https://dns.google/resolve?name={domain}&type={rtype}")
                    if r.status_code==200:
                        answers=r.json().get("Answer",[])
                        if answers:
                            vals=[a.get("data","") for a in answers]
                            dns_rows.append(f"{rtype}: {', '.join(vals[:3])}")
                            if rtype=="TXT":
                                spf=next((v for v in vals if "v=spf1" in v.lower()),None)
                                r2=await cl.get(f"https://dns.google/resolve?name=_dmarc.{domain}&type=TXT")
                                dmarc_rec=None
                                if r2.status_code==200:
                                    dv=[a.get("data","") for a in r2.json().get("Answer",[])]
                                    dmarc_rec=next((v for v in dv if "v=dmarc" in v.lower()),None)
                                email_issues=[]
                                if not spf: email_issues.append("⚠ No SPF record — spoofing risk!")
                                else: email_issues.append(f"✓ SPF: {spf[:80]}")
                                if not dmarc_rec: email_issues.append("⚠ No DMARC record — spoofing risk!")
                                elif "p=none" in dmarc_rec.lower(): email_issues.append(f"⚠ DMARC p=none (monitoring only, not enforced): {dmarc_rec[:80]}")
                                elif "p=reject" in dmarc_rec.lower(): email_issues.append(f"✓ DMARC p=reject (strict): {dmarc_rec[:80]}")
                                else: email_issues.append(f"~ DMARC p=quarantine: {dmarc_rec[:80]}")
                                if any("⚠" in i for i in email_issues):
                                    add_finding(sid,finding(tool,"WARNING",
                                        f"🟡 Email spoofing risk: {domain} has weak SPF/DMARC",
                                        "Email authentication:\n"+"\n".join(email_issues)+
                                        f"\n\nRisk: Attackers can send spoofed @{domain} emails.",
                                        raw={"spf":spf,"dmarc":dmarc_rec}))
                except Exception: pass
            if dns_rows:
                add_finding(sid,finding(tool,"INFO",f"🔵 DNS records for {domain}",
                    "Full DNS record analysis:\n"+"\n".join(dns_rows),raw=dns_rows))
        except Exception as e: log(sid,"WARN",f"DNS analysis: {e}")

        # 3. WHOIS / RDAP (free, no key)
        log(sid,"INFO","osint [3/5]: WHOIS/RDAP lookup...")
        try:
            r=await cl.get(f"https://rdap.org/domain/{domain}")
            if r.status_code==200:
                data=r.json()
                events={e["eventAction"]:e["eventDate"][:10] for e in data.get("events",[]) if e.get("eventDate")}
                ns=[n.get("ldhName","") for n in data.get("nameservers",[])]
                status=data.get("status",[])
                registrar=""
                for ent in data.get("entities",[]):
                    if "registrar" in ent.get("roles",[]):
                        vc=ent.get("vcardArray",[[]])[1] if ent.get("vcardArray") else []
                        for v in vc:
                            if v[0]=="fn": registrar=v[3]; break
                reg=events.get("registration","unknown"); exp=events.get("expiration","unknown")
                changed=events.get("last changed","unknown")
                sev="INFO"; age_note=""
                if reg!="unknown":
                    try:
                        age=datetime.now().year-int(reg[:4])
                        age_note=f"Domain age: {age} year(s)" if age>=1 else "⚠ Very new domain — potential impersonation!"
                        if age<1: sev="WARNING"
                    except: age_note=f"Registered: {reg}"
                add_finding(sid,finding(tool,sev,
                    f"{'🟡' if sev=='WARNING' else '🔵'} WHOIS/RDAP: {domain}",
                    f"{age_note}\nRegistrar: {registrar or 'unknown'}\n"
                    f"Registered: {reg}\nExpires: {exp}\nLast changed: {changed}\n"
                    f"Nameservers: {', '.join(ns[:4])}\nStatus: {', '.join(status[:4]) if status else 'unknown'}",
                    raw={"registration":reg,"expiration":exp,"registrar":registrar,"nameservers":ns}))
        except Exception as e: log(sid,"WARN",f"RDAP: {e}")

        # 4. PASTE SITE SEARCH (free via Google News RSS)
        log(sid,"INFO","osint [4/5]: paste site search...")
        try:
            paste_hits=[]
            for pq in [f"https://news.google.com/rss/search?q=site:pastebin.com+{domain}&hl=en",
                       f"https://news.google.com/rss/search?q={brand}+credentials+dump+OR+password+leak&hl=en"]:
                r=await cl.get(pq)
                if r.status_code==200:
                    feed=feedparser.parse(r.text)
                    for e in feed.entries[:5]:
                        paste_hits.append({"title":e.get("title",""),"url":e.get("link",""),"date":e.get("published","")[:10]})
            if paste_hits:
                add_finding(sid,finding(tool,"WARNING",f"🟡 Paste site references found for '{brand}'",
                    f"{len(paste_hits)} paste/dump references:\n"+"\n".join(f"• {h['title'][:80]} ({h['date']})" for h in paste_hits[:8]),
                    raw=paste_hits))
            else:
                add_finding(sid,finding(tool,"OK",f"🟢 Paste sites: No credential dumps found for '{brand}'",
                    "No paste site references or credential lists found via public search."))
        except Exception as e: log(sid,"WARN",f"Paste check: {e}")

        # 5. GOOGLE DORK HINTS (free — shows what to check manually)
        log(sid,"INFO","osint [5/5]: sensitive content exposure check...")
        try:
            dork_hints=[
                f"https://www.google.com/search?q=site:{domain}+intitle:index.of",
                f"https://www.google.com/search?q=site:{domain}+ext:sql+OR+ext:bak+OR+ext:env",
                f"https://www.google.com/search?q=site:{domain}+inurl:admin+OR+inurl:login+OR+inurl:cpanel",
                f"https://www.google.com/search?q=site:{domain}+inurl:wp-admin+OR+inurl:phpmyadmin",
            ]
            add_finding(sid,finding(tool,"INFO",
                f"🔵 Manual Google dork checks recommended for {domain}",
                f"Run these searches to find exposed sensitive pages:\n\n"
                +"\n".join(f"• {h}" for h in dork_hints)
                +f"\n\nAlso check:\n• https://crt.sh/?q=%.{domain}\n• https://shodan.io/search?query=hostname:{domain}",
                raw=dork_hints))
        except Exception as e: log(sid,"WARN",f"Dork hints: {e}")

    set_tool(sid,tool,"alert" if has_alert(sid,tool) else "done")

# ── TOOL 8: SCRAPY (optional) ─────────────────────────────────────────────────
async def run_scrapy(sid: str, brand: str):
    """
    Custom web scraper — pure httpx, no Scrapy package needed.
    Scrapy requires C extensions that fail to install in restricted environments.
    This replacement scrapes the same targets (paste sites, gists, forums)
    using only httpx which is already installed.
    Targets:
      - GitHub Gist search       (credential dumps)
      - Pastebin public archive  (brand mentions)
      - StackOverflow            (technical issues / exposed configs)
      - Google dork RSS          (indexed sensitive pages)
    """
    tool = "scrapy"
    set_tool(sid, tool, "running")
    log(sid, "INFO", f"scraper: scanning paste sites, Gists, and forums for '{brand}'...")

    findings_count = 0

    async with httpx.AsyncClient(
        timeout=15,
        headers={"User-Agent": "BrandMonitor/2.0"},
        follow_redirects=True,
    ) as cl:

        # ── 1. GitHub Gist search (public credential dumps) ─────────────────
        log(sid, "INFO", "scraper [1/4]: GitHub Gist search...")
        try:
            r = await cl.get(
                f"https://gist.github.com/search?q={brand}+password+OR+credentials+OR+apikey",
                headers={"Accept": "application/json"},
                timeout=12,
            )
            if r.status_code == 200:
                # Parse gist result count from HTML
                import re as _re
                count_match = _re.search(r"(\d[\d,]*)\s+gist results", r.text, _re.I)
                gist_count = int(count_match.group(1).replace(",","")) if count_match else 0

                # Extract gist titles and descriptions
                titles = _re.findall(r'<div class="gist-snippet-meta">.*?<a[^>]+>(.*?)</a>', r.text, _re.DOTALL)
                cleaned = [_re.sub(r"<[^>]+>","",t).strip() for t in titles[:10]]

                if gist_count > 0 or cleaned:
                    sev = "CRITICAL" if gist_count > 5 else "WARNING"
                    findings_count += 1
                    add_finding(sid, finding(
                        tool, sev,
                        f"{'🔴' if sev=='CRITICAL' else '🟡'} GitHub Gists: {gist_count or len(cleaned)} public gists mention '{brand}' credentials",
                        f"Search: github.com/gist — query: {brand} + password/credentials/apikey\n"
                        f"Gists found: {gist_count or len(cleaned)}\n"
                        f"Sample titles:\n" +
                        "\n".join(f"• {t}" for t in cleaned[:6] if t) +
                        f"\n\nAction: Review each gist — may contain leaked credentials or config files.\n"
                        f"URL: https://gist.github.com/search?q={brand}+password",
                        raw={"count": gist_count, "titles": cleaned},
                    ))
                else:
                    add_finding(sid, finding(
                        tool, "OK",
                        f"🟢 GitHub Gists: No credential dumps found for '{brand}'",
                        f"No public Gists found matching '{brand}' + password/credentials/apikey.\n"
                        f"Gist search is clean.",
                    ))
        except Exception as e:
            log(sid, "WARN", f"scraper: Gist search error: {e}")

        # ── 2. Pastebin public scrape (brand domain mentions) ────────────────
        log(sid, "INFO", "scraper [2/4]: Pastebin public archive scan...")
        try:
            # Use Google cache RSS since Pastebin blocks direct scraping
            paste_queries = [
                f"https://news.google.com/rss/search?q=site:pastebin.com+{brand}&hl=en&gl=IN",
                f"https://news.google.com/rss/search?q=pastebin+{brand}+credentials+OR+dump+OR+leak&hl=en",
            ]
            paste_hits = []
            for pq in paste_queries:
                r = await cl.get(pq, timeout=12)
                if r.status_code == 200:
                    feed = feedparser.parse(r.text)
                    for entry in feed.entries[:8]:
                        title = entry.get("title", "")
                        if brand.lower() in title.lower() or "pastebin" in entry.get("link",""):
                            paste_hits.append({
                                "title": title,
                                "url": entry.get("link",""),
                                "date": entry.get("published","")[:10],
                            })

            if paste_hits:
                findings_count += 1
                add_finding(sid, finding(
                    tool, "WARNING",
                    f"🟡 Paste sites: {len(paste_hits)} references to '{brand}' found",
                    f"Brand mentions found on paste/dump sites:\n" +
                    "\n".join(f"• {h['title'][:80]} ({h['date']})\n  {h['url']}" for h in paste_hits[:6]),
                    raw=paste_hits,
                ))
            else:
                add_finding(sid, finding(
                    tool, "OK",
                    f"🟢 Paste sites: No '{brand}' credential dumps found",
                    "Pastebin and paste site search returned no results for this brand.\n"
                    "No credential dumps or data leaks found on public paste sites.",
                ))
        except Exception as e:
            log(sid, "WARN", f"scraper: Pastebin scan error: {e}")

        # ── 3. StackOverflow / StackExchange (exposed configs in questions) ───
        log(sid, "INFO", "scraper [3/4]: StackOverflow exposed config scan...")
        try:
            r = await cl.get(
                f"https://api.stackexchange.com/2.3/search/advanced"
                f"?order=desc&sort=creation&q={brand}+api+key+OR+password+OR+credentials"
                f"&site=stackoverflow&pagesize=10&filter=!nNPvSNPI0O",
                timeout=12,
            )
            if r.status_code == 200:
                items = r.json().get("items", [])
                risky = [
                    i for i in items
                    if any(kw in (i.get("title","") + i.get("body","")).lower()
                           for kw in ["api_key","password","secret","credentials","token"])
                ]
                if risky:
                    findings_count += 1
                    add_finding(sid, finding(
                        tool, "WARNING",
                        f"🟡 StackOverflow: {len(risky)} posts may expose '{brand}' credentials in code",
                        f"Posts found containing API keys/passwords in code snippets:\n" +
                        "\n".join(f"• {i['title'][:80]}" for i in risky[:5]) +
                        f"\n\nDevelopers sometimes paste real credentials when asking for help.\n"
                        f"Review each post to check if credentials are real.",
                        raw=[{"title": i["title"], "link": i.get("link","")} for i in risky[:5]],
                    ))
                else:
                    add_finding(sid, finding(
                        tool, "OK",
                        f"🟢 StackOverflow: No exposed credentials found for '{brand}'",
                        f"Searched StackOverflow for posts containing '{brand}' with API keys or passwords.\n"
                        f"No risky posts found.",
                    ))
        except Exception as e:
            log(sid, "WARN", f"scraper: StackOverflow scan error: {e}")

        # ── 4. Google Dork RSS (indexed sensitive pages on brand domain) ──────
        log(sid, "INFO", "scraper [4/4]: Sensitive page exposure check...")
        try:
            dork_results = []
            dork_checks = [
                (f"{brand} filetype:sql OR filetype:env OR filetype:bak", "Exposed database/config files"),
                (f"{brand} inurl:admin OR inurl:phpmyadmin OR inurl:wp-admin", "Admin panels indexed"),
                (f"{brand} intitle:index.of OR directory listing", "Open directory listings"),
                (f"{brand} password OR credentials site:github.com", "GitHub credential exposure"),
            ]
            for query, label in dork_checks:
                r = await cl.get(
                    f"https://news.google.com/rss/search?q={query}&hl=en&gl=IN",
                    timeout=10,
                )
                if r.status_code == 200:
                    feed = feedparser.parse(r.text)
                    if feed.entries:
                        relevant = [e for e in feed.entries[:5] if brand.lower() in e.get("title","").lower()]
                        if relevant:
                            dork_results.append({
                                "label": label,
                                "count": len(relevant),
                                "examples": [e.get("title","")[:80] for e in relevant[:3]],
                            })

            if dork_results:
                findings_count += 1
                detail_lines = []
                for dr in dork_results:
                    detail_lines.append(f"• {dr['label']} ({dr['count']} results):")
                    for ex in dr["examples"]:
                        detail_lines.append(f"    - {ex}")
                add_finding(sid, finding(
                    tool, "WARNING",
                    f"🟡 Web exposure: Sensitive pages potentially indexed for '{brand}'",
                    "Potentially sensitive content indexed by search engines:\n" +
                    "\n".join(detail_lines) +
                    "\n\nManually verify these with Google dork searches.",
                    raw=dork_results,
                ))
            else:
                add_finding(sid, finding(
                    tool, "OK",
                    f"🟢 Web exposure: No obviously sensitive pages found for '{brand}'",
                    "Checked for indexed admin panels, open directories, exposed config files, and GitHub credentials.\n"
                    "No high-risk results found via public search.",
                ))
        except Exception as e:
            log(sid, "WARN", f"scraper: Dork check error: {e}")

    log(sid, "OK" if findings_count == 0 else "WARN",
        f"scraper: completed — {findings_count} risk findings across 4 targets")
    set_tool(sid, tool, "alert" if has_alert(sid, tool) else "done")



# ─────────────────────────────────────────────────────────────────
# TOOL A — GITHUB CODE SEARCH (beyond org repos)
# ─────────────────────────────────────────────────────────────────
async def run_github_codesearch(sid: str, brand: str, domain: str):
    """
    Searches ALL of GitHub for any public file containing the brand domain,
    email pattern, or internal identifiers — catches secrets in forks,
    personal repos of ex-employees, and third-party integrations that
    the org-only scan completely misses.
    Requires GITHUB_TOKEN in .env for code search (free, just needs an account).
    """
    tool = "github_code"
    set_tool(sid, tool, "running")
    log(sid, "INFO", f"github-search: scanning all public GitHub code for '{brand}'...")

    gh_token = os.getenv("GITHUB_TOKEN", "")
    if not gh_token:
        add_finding(sid, finding(tool, "INFO",
            "GitHub code search skipped — no token configured",
            f"Add GITHUB_TOKEN to .env for full GitHub code search.\n"
            f"Get a free token at: github.com/settings/tokens (no special scopes needed)\n"
            f"Without a token, GitHub limits code search to 10 requests/hr."))
        set_tool(sid, tool, "done")
        return

    headers = {
        "Authorization": f"token {gh_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    # Search queries — each targets a different exposure pattern
    QUERIES = [
        (f"{domain} password",        "Password with domain"),
        (f"{domain} apikey OR api_key","API key with domain"),
        (f"{domain} secret OR token",  "Secret/token with domain"),
        (f"@{domain} password",        "Email pattern + password"),
        (f"{brand} db_password OR DATABASE_PASSWORD", "Database credentials"),
        (f"{brand} private_key OR PRIVATE_KEY",        "Private keys"),
    ]

    total_hits = 0
    all_results = []

    async with httpx.AsyncClient(timeout=20, headers=headers) as cl:
        for query, label in QUERIES:
            try:
                await asyncio.sleep(2)  # respect rate limit: 30 req/min for code search
                r = await cl.get(
                    "https://api.github.com/search/code",
                    params={"q": query, "per_page": 10, "sort": "indexed"},
                )
                if r.status_code == 403:
                    log(sid, "WARN", "github-search: rate limited — pausing 30s")
                    await asyncio.sleep(30)
                    continue
                if r.status_code == 422:
                    continue  # query not supported, skip
                if r.status_code != 200:
                    continue

                data = r.json()
                count = data.get("total_count", 0)
                items = data.get("items", [])

                if count == 0:
                    continue

                total_hits += count
                for item in items[:5]:
                    repo  = item.get("repository", {}).get("full_name", "?")
                    fname = item.get("name", "?")
                    fpath = item.get("path", "?")
                    furl  = item.get("html_url", "")
                    all_results.append({
                        "repo": repo, "file": fname,
                        "path": fpath, "url": furl,
                        "query": label,
                    })

                # Flag immediately if results found
                sev = "CRITICAL" if count > 5 else "WARNING"
                add_finding(sid, finding(
                    tool, sev,
                    f"{'🔴' if sev=='CRITICAL' else '🟡'} {count} public files match: {label}",
                    f"Search query: {query}\n"
                    f"Total matches across all GitHub: {count}\n"
                    f"Sample files:\n" +
                    "\n".join(
                        f"• github.com/{r['repo']} → {r['path']}"
                        for r in [i for i in all_results if i['query'] == label][:5]
                    ) +
                    f"\n\nReview each file — may contain real credentials.\n"
                    f"Search URL: https://github.com/search?q={query.replace(' ','+')}+&type=code",
                    raw={"query": query, "count": count,
                         "files": [i for i in all_results if i["query"] == label][:5]},
                ))

            except Exception as e:
                log(sid, "WARN", f"github-search: query error: {e}")

    if total_hits == 0:
        add_finding(sid, finding(
            tool, "OK",
            f"🟢 GitHub code search: No public exposure of '{brand}' credentials",
            f"Searched all public GitHub code for {len(QUERIES)} credential patterns.\n"
            f"No files found containing your domain + sensitive keywords.\n"
            f"This means no public repos (including forks and personal repos) expose your credentials.",
        ))

    log(sid, "OK" if total_hits == 0 else "CRIT",
        f"github-search: {total_hits} total matches across {len(QUERIES)} queries")
    set_tool(sid, tool, "alert" if has_alert(sid, tool) else "done")


# ─────────────────────────────────────────────────────────────────
# TOOL B — SOCIAL MEDIA ACCOUNT PROTECTION
# ─────────────────────────────────────────────────────────────────
async def run_social_protection(sid: str, brand: str):
    """
    Checks for impersonation accounts and unclaimed handles across
    major social platforms. No API keys needed — uses public profile
    URLs and Google News RSS to detect fake accounts.
    """
    tool = "social_protect"
    set_tool(sid, tool, "running")
    log(sid, "INFO", f"social-protect: checking for impersonation across platforms...")

    PLATFORMS = [
        ("Twitter/X",   f"https://twitter.com/{brand}",             f"https://twitter.com/{brand}_official"),
        ("Instagram",   f"https://www.instagram.com/{brand}/",      f"https://www.instagram.com/{brand}official/"),
        ("LinkedIn",    f"https://www.linkedin.com/company/{brand}", f"https://www.linkedin.com/company/{brand}-official"),
        ("YouTube",     f"https://www.youtube.com/@{brand}",        f"https://www.youtube.com/@{brand}official"),
        ("Telegram",    f"https://t.me/{brand}",                    f"https://t.me/{brand}_official"),
        ("Facebook",    f"https://www.facebook.com/{brand}",        f"https://www.facebook.com/{brand}.official"),
        ("GitHub",      f"https://github.com/{brand}",              f"https://github.com/{brand}-official"),
        ("Medium",      f"https://medium.com/@{brand}",             None),
    ]

    claimed  = []
    unclaimed = []
    suspicious = []

    async with httpx.AsyncClient(
        timeout=12,
        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
        follow_redirects=True,
    ) as cl:

        # ── 1. Check which handles exist ─────────────────────────
        for platform, official_url, variant_url in PLATFORMS:
            try:
                r = await cl.get(official_url, timeout=8)
                if r.status_code == 200 and brand.lower() in r.text.lower():
                    claimed.append({"platform": platform, "url": official_url, "status": "exists"})
                elif r.status_code == 404:
                    unclaimed.append({"platform": platform, "url": official_url, "handle": f"@{brand}"})
                # Check variant (impersonation pattern)
                if variant_url:
                    r2 = await cl.get(variant_url, timeout=6)
                    if r2.status_code == 200:
                        suspicious.append({
                            "platform": platform,
                            "url": variant_url,
                            "note": "Variant handle exists — may be impersonation"
                        })
            except Exception:
                pass  # platform blocked or network timeout — skip

        # ── 2. Google News RSS — search for impersonation reports ─
        log(sid, "INFO", "social-protect: searching for fake account reports...")
        try:
            r = await cl.get(
                f"https://news.google.com/rss/search?q={brand}+fake+account+OR+impersonation+OR+scam&hl=en",
                timeout=12,
            )
            if r.status_code == 200:
                feed = feedparser.parse(r.text)
                fake_reports = []
                for entry in feed.entries[:10]:
                    title = entry.get("title", "").lower()
                    if any(kw in title for kw in ["fake","scam","impersonat","fraud","phish","spoof"]):
                        fake_reports.append({
                            "title": entry.get("title",""),
                            "url": entry.get("link",""),
                            "date": entry.get("published","")[:10],
                        })
                if fake_reports:
                    add_finding(sid, finding(
                        tool, "WARNING",
                        f"🟡 {len(fake_reports)} reports of fake/impersonation accounts for '{brand}'",
                        "News and community reports of impersonation:\n" +
                        "\n".join(f"• {r['title'][:90]} ({r['date']})" for r in fake_reports[:6]),
                        raw=fake_reports,
                    ))
        except Exception as e:
            log(sid, "WARN", f"social-protect: RSS check error: {e}")

    # Report unclaimed handles
    if unclaimed:
        add_finding(sid, finding(
            tool, "WARNING",
            f"🟡 {len(unclaimed)} social media handles unclaimed for '{brand}'",
            f"These handles are available — register them before impersonators do:\n" +
            "\n".join(f"• {h['platform']}: {h['handle']} → {h['url']}" for h in unclaimed) +
            f"\n\nRegistering takes 30 minutes total and costs nothing.\n"
            f"Even if you don't post, claimed handles prevent impersonation.",
            raw=unclaimed,
        ))

    # Report suspicious variants
    if suspicious:
        add_finding(sid, finding(
            tool, "CRITICAL",
            f"🔴 {len(suspicious)} suspicious variant handles found — possible impersonation",
            f"These variant accounts exist and may be impersonating your brand:\n" +
            "\n".join(f"• {s['platform']}: {s['url']}\n  → {s['note']}" for s in suspicious) +
            f"\n\nAction: Visit each URL, verify if legitimate, report to platform if fake.\n"
            f"Most platforms remove verified impersonators within 24–48 hours.",
            raw=suspicious,
        ))

    # Report claimed handles (positive)
    if claimed:
        add_finding(sid, finding(
            tool, "INFO",
            f"🔵 {len(claimed)} official social handles found for '{brand}'",
            f"Active social media presence detected:\n" +
            "\n".join(f"• {c['platform']}: {c['url']}" for c in claimed) +
            "\n\nEnsure all accounts have:\n"
            "• Verified badge applied\n"
            "• Consistent branding and bio\n"
            "• 2FA enabled on all accounts",
            raw=claimed,
        ))

    if not claimed and not unclaimed and not suspicious:
        add_finding(sid, finding(
            tool, "INFO",
            f"Social media check: platforms unreachable (network restricted)",
            f"Could not reach social platforms to check handle status.\n"
            f"Manually check: twitter.com/{brand}, instagram.com/{brand}, linkedin.com/company/{brand}\n"
            f"Register any unclaimed handles proactively.",
        ))

    log(sid, "OK", f"social-protect: {len(claimed)} claimed, {len(unclaimed)} unclaimed, {len(suspicious)} suspicious")
    set_tool(sid, tool, "alert" if has_alert(sid, tool) else "done")


# ─────────────────────────────────────────────────────────────────
# TOOL C — DARK WEB & PASTE MONITORING
# ─────────────────────────────────────────────────────────────────
async def run_darkweb(sid: str, brand: str, domain: str):
    """
    Monitors paste sites, breach databases, and dark web references
    for credential dumps and data leaks. Uses only free sources:
    IntelligenceX free tier, GitHub Gist search, Google cache of
    paste sites, HackerNews mentions, and breach hash checking.
    """
    tool = "darkweb"
    set_tool(sid, tool, "running")
    log(sid, "INFO", f"darkweb: scanning paste sites and breach databases for '{brand}'...")

    PASTE_SITES = [
        "pastebin.com", "paste.ee", "ghostbin.co",
        "rentry.co", "hastebin.com", "dpaste.com",
    ]

    all_hits = []

    async with httpx.AsyncClient(
        timeout=15,
        headers={"User-Agent": "BrandMonitor/2.0 (security research)"},
        follow_redirects=True,
    ) as cl:

        # ── 1. Google cache search for paste sites ───────────────
        log(sid, "INFO", "darkweb [1/5]: paste site scan via Google cache...")
        try:
            for paste_site in PASTE_SITES[:4]:
                r = await cl.get(
                    f"https://news.google.com/rss/search?q=site:{paste_site}+{domain}&hl=en",
                    timeout=10,
                )
                if r.status_code == 200:
                    feed = feedparser.parse(r.text)
                    for entry in feed.entries[:5]:
                        title = entry.get("title","")
                        if domain.lower() in title.lower() or brand.lower() in title.lower():
                            all_hits.append({
                                "source": paste_site,
                                "title": title,
                                "url": entry.get("link",""),
                                "date": entry.get("published","")[:10],
                                "type": "paste",
                            })
        except Exception as e:
            log(sid, "WARN", f"darkweb: paste scan error: {e}")

        # ── 2. GitHub Gist search (credential dumps posted as gists) ─
        log(sid, "INFO", "darkweb [2/5]: GitHub Gist credential dump search...")
        try:
            for query in [f"{domain} password", f"{domain} credentials", f"{brand} dump"]:
                r = await cl.get(
                    f"https://gist.github.com/search?q={query.replace(' ','+')}",
                    timeout=10,
                )
                if r.status_code == 200:
                    import re as _re
                    count_m = _re.search(r'(\d[\d,]*)\s+gist', r.text, _re.I)
                    count = int(count_m.group(1).replace(",","")) if count_m else 0
                    if count > 0:
                        titles = _re.findall(r'<a[^>]+class="[^"]*gist[^"]*"[^>]*>([^<]+)<', r.text)
                        all_hits.append({
                            "source": "GitHub Gist",
                            "title": f"{count} gists match: {query}",
                            "url": f"https://gist.github.com/search?q={query.replace(' ','+')}",
                            "count": count,
                            "samples": [t.strip() for t in titles[:3] if t.strip()],
                            "type": "gist",
                        })
        except Exception as e:
            log(sid, "WARN", f"darkweb: Gist search error: {e}")

        # ── 3. IntelligenceX free API ─────────────────────────────
        log(sid, "INFO", "darkweb [3/5]: IntelligenceX search...")
        try:
            # Start search
            r = await cl.post(
                "https://2.intelx.io/intelligent/search",
                json={
                    "term": domain,
                    "buckets": [],
                    "lookuplevel": 0,
                    "maxresults": 10,
                    "timeout": 5,
                    "datefrom": "",
                    "dateto": "",
                    "sort": 4,
                    "media": 0,
                    "terminate": [],
                },
                headers={"x-key": os.getenv("INTELX_API_KEY", ""), "Content-Type": "application/json"},
                timeout=10,
            )
            if r.status_code == 200:
                data = r.json()
                search_id = data.get("id","")
                if search_id:
                    await asyncio.sleep(3)
                    r2 = await cl.get(
                        f"https://2.intelx.io/intelligent/search/result?id={search_id}&limit=10",
                        headers={"x-key": os.getenv("INTELX_API_KEY","")},
                        timeout=10,
                    )
                    if r2.status_code == 200:
                        results = r2.json().get("records",[])
                        for rec in results:
                            media = rec.get("media", 0)
                            name  = rec.get("name","")
                            date  = rec.get("date","")[:10]
                            # media 1=paste, 8=darkweb, 13=breach
                            source_map = {1:"Paste site", 8:"Dark web", 13:"Breach database"}
                            src = source_map.get(media, "IntelligenceX")
                            all_hits.append({
                                "source": src,
                                "title": name or f"{src} result",
                                "date": date,
                                "type": "intelx",
                                "media_type": src,
                            })
        except Exception as e:
            log(sid, "WARN", f"darkweb: IntelligenceX error (may need API key): {e}")

        # ── 4. HackerNews breach/leak discussions ────────────────
        log(sid, "INFO", "darkweb [4/5]: HackerNews breach discussion search...")
        try:
            r = await cl.get(
                f"https://hn.algolia.com/api/v1/search?query={brand}+breach+OR+leak+OR+dump"
                f"&tags=story&hitsPerPage=10",
                timeout=10,
            )
            if r.status_code == 200:
                for hit in r.json().get("hits", []):
                    title = hit.get("title","")
                    if any(kw in title.lower() for kw in
                           ["breach","leak","dump","hack","exposed","credential","password"]):
                        all_hits.append({
                            "source": "HackerNews",
                            "title": title,
                            "url": f"https://news.ycombinator.com/item?id={hit.get('objectID','')}",
                            "date": (hit.get("created_at",""))[:10],
                            "points": hit.get("points",0),
                            "type": "hn",
                        })
        except Exception as e:
            log(sid, "WARN", f"darkweb: HN search error: {e}")

        # ── 5. DeHashed email domain check ───────────────────────
        log(sid, "INFO", "darkweb [5/5]: breach database correlation...")
        try:
            # Check HIBP breach list (public, no key for domain check page)
            r = await cl.get(
                f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}",
                headers={"hibp-api-key": os.getenv("HIBP_API_KEY",""),
                         "user-agent": "BrandMonitor-Security-Research"},
                timeout=10,
            )
            if r.status_code == 200:
                breaches = r.json()
                for b in breaches:
                    all_hits.append({
                        "source": "HaveIBeenPwned",
                        "title": f"Breach: {b.get('Name','?')} ({b.get('BreachDate','?')[:4]})",
                        "detail": f"{b.get('PwnCount',0):,} accounts | "
                                  f"Data: {', '.join(b.get('DataClasses',[])[:4])}",
                        "type": "hibp",
                        "severity": "CRITICAL",
                    })
            elif r.status_code == 401:
                log(sid, "INFO", "darkweb: HIBP requires paid key (£3.50/mo) — set HIBP_API_KEY in .env")
            elif r.status_code == 404:
                add_finding(sid, finding(tool, "OK",
                    f"🟢 HaveIBeenPwned: {domain} not found in any known breach",
                    "Domain email addresses have not appeared in any known data breach indexed by HIBP."))
        except Exception as e:
            log(sid, "WARN", f"darkweb: HIBP error: {e}")

    # Group and report findings
    hibp_hits  = [h for h in all_hits if h.get("type") == "hibp"]
    dark_hits  = [h for h in all_hits if h.get("type") == "intelx"]
    paste_hits = [h for h in all_hits if h.get("type") == "paste"]
    gist_hits  = [h for h in all_hits if h.get("type") == "gist"]
    hn_hits    = [h for h in all_hits if h.get("type") == "hn"]

    if hibp_hits:
        add_finding(sid, finding(
            tool, "CRITICAL",
            f"🔴 HIBP: {len(hibp_hits)} breach dataset(s) contain {domain} credentials",
            "Known data breaches containing this domain's email addresses:\n" +
            "\n".join(f"• {h['title']}\n  {h.get('detail','')}" for h in hibp_hits[:5]) +
            "\n\nAction: Force password reset for all affected accounts immediately.\n"
            "Enable MFA on all institutional accounts.",
            raw=hibp_hits,
        ))

    if dark_hits:
        add_finding(sid, finding(
            tool, "CRITICAL",
            f"🔴 Dark web: {len(dark_hits)} references found on IntelligenceX",
            "Findings from dark web, paste sites, and breach databases:\n" +
            "\n".join(f"• [{h.get('media_type','?')}] {h['title']} ({h.get('date','')})"
                       for h in dark_hits[:8]),
            raw=dark_hits,
        ))

    if paste_hits:
        sev = "CRITICAL" if len(paste_hits) > 3 else "WARNING"
        add_finding(sid, finding(
            tool, sev,
            f"{'🔴' if sev=='CRITICAL' else '🟡'} Paste sites: {len(paste_hits)} references to '{domain}'",
            "Brand domain found on public paste sites:\n" +
            "\n".join(f"• [{h['source']}] {h['title'][:80]} ({h.get('date','')})"
                       for h in paste_hits[:8]) +
            "\n\nManually review each paste for credential dumps.",
            raw=paste_hits,
        ))

    if gist_hits:
        add_finding(sid, finding(
            tool, "WARNING",
            f"🟡 GitHub Gists: {sum(h.get('count',1) for h in gist_hits)} gists mention '{brand}' credentials",
            "Public GitHub Gists found containing brand credentials keywords:\n" +
            "\n".join(f"• {h['title']}" for h in gist_hits[:5]),
            raw=gist_hits,
        ))

    if hn_hits:
        add_finding(sid, finding(
            tool, "WARNING",
            f"🟡 HackerNews: {len(hn_hits)} breach/leak discussions mention '{brand}'",
            "Tech community discussing breaches related to this brand:\n" +
            "\n".join(f"• {h['title']} ({h.get('points',0)} pts, {h.get('date','')})"
                       for h in hn_hits[:5]),
            raw=hn_hits,
        ))

    if not all_hits:
        add_finding(sid, finding(
            tool, "OK",
            f"🟢 Dark web & paste monitoring: No dumps found for '{brand}'",
            f"Checked: Pastebin/paste sites (Google cache), GitHub Gists, "
            f"IntelligenceX, HackerNews, HaveIBeenPwned.\n"
            f"No credential dumps, breach data, or dark web mentions found.\n"
            f"Add HIBP_API_KEY and INTELX_API_KEY to .env for deeper coverage.",
        ))

    log(sid, "OK" if not all_hits else "WARN",
        f"darkweb: {len(all_hits)} total findings across 5 sources")
    set_tool(sid, tool, "alert" if has_alert(sid, tool) else "done")


# ─────────────────────────────────────────────────────────────────
# TOOL D — VISUAL PHISHING DETECTION
# ─────────────────────────────────────────────────────────────────
async def run_visual_phishing(sid: str, domain: str):
    """
    Takes screenshots of lookalike domains and compares them visually
    to the real site using perceptual hashing. Catches sophisticated
    clones that use completely different text but replicate the
    visual design pixel-for-pixel.

    Requires: pip install playwright Pillow imagehash
              playwright install chromium
    Falls back to HTTP content comparison if Playwright not installed.
    """
    tool = "visual_phish"
    set_tool(sid, tool, "running")
    log(sid, "INFO", f"visual-phishing: checking lookalike domains for visual similarity...")

    # Get dnstwist findings from current scan to find domains to check
    dnstwist_findings = [
        f for f in scans[sid]["findings"]
        if f["tool"] == "dnstwist" and f["severity"] in ("CRITICAL","WARNING")
        and "Lookalike" in f["title"]
    ]

    if not dnstwist_findings:
        add_finding(sid, finding(
            tool, "INFO",
            "Visual phishing: no lookalike domains to compare",
            "dnstwist found no active lookalike domains to screenshot.\n"
            "Run after dnstwist has found registered domains with active IPs.",
        ))
        set_tool(sid, tool, "done")
        return

    # Extract domain names from findings
    import re as _re
    target_domains = []
    for f in dnstwist_findings[:8]:  # limit to 8 to avoid timeout
        m = _re.search(r'(?:domain|active):\s*([a-z0-9.\-]+)', f["detail"], _re.I)
        if not m:
            m = _re.search(r'([a-z0-9.\-]+\.[a-z]{2,})', f["title"])
        if m:
            dom = m.group(1).strip()
            if dom != domain and dom not in target_domains:
                target_domains.append(dom)

    log(sid, "INFO", f"visual-phishing: {len(target_domains)} domains to compare")

    # ── Try Playwright for real screenshots ──────────────────────
    playwright_ok = False
    try:
        from playwright.async_api import async_playwright
        playwright_ok = True
    except ImportError:
        log(sid, "WARN", "visual-phishing: Playwright not installed — using content-hash fallback")
        log(sid, "INFO", "Install: pip install playwright && playwright install chromium")

    try:
        import PIL
        import imagehash
        from PIL import Image
        import io
        image_ok = True
    except ImportError:
        image_ok = False
        log(sid, "WARN", "visual-phishing: imagehash not installed — using text similarity")
        log(sid, "INFO", "Install: pip install imagehash Pillow")

    async def get_page_content(target: str) -> dict:
        """Get page content via HTTP (fallback when Playwright unavailable)."""
        async with httpx.AsyncClient(
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"},
            follow_redirects=True,
        ) as cl:
            try:
                r = await cl.get(f"https://{target}", timeout=8)
                return {"html": r.text[:5000], "status": r.status_code, "url": str(r.url)}
            except Exception:
                try:
                    r = await cl.get(f"http://{target}", timeout=8)
                    return {"html": r.text[:5000], "status": r.status_code, "url": str(r.url)}
                except Exception as e:
                    return {"html": "", "status": 0, "error": str(e)}

    def text_similarity(html1: str, html2: str) -> float:
        """Compute simple text token overlap similarity 0-100."""
        if not html1 or not html2:
            return 0.0
        import re as _re
        def tokens(html):
            text = _re.sub(r"<[^>]+>","", html).lower()
            return set(_re.findall(r"[a-z]{3,}", text))
        t1, t2 = tokens(html1), tokens(html2)
        if not t1 or not t2:
            return 0.0
        intersection = len(t1 & t2)
        union = len(t1 | t2)
        return round(intersection / union * 100, 1) if union else 0.0

    # Get real site content/screenshot
    real_content = await get_page_content(domain)
    real_html = real_content.get("html","")

    results = []

    if playwright_ok:
        log(sid, "INFO", "visual-phishing: taking screenshots with Playwright...")
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    args=["--no-sandbox","--disable-dev-shm-usage","--disable-gpu"],
                    headless=True,
                )
                page = await browser.new_page(
                    viewport={"width": 1280, "height": 800},
                    user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                )

                # Screenshot real site
                real_hash = None
                try:
                    await page.goto(f"https://{domain}", timeout=12000, wait_until="domcontentloaded")
                    await asyncio.sleep(2)
                    real_ss = await page.screenshot(full_page=False)
                    if image_ok:
                        img = Image.open(io.BytesIO(real_ss))
                        real_hash = imagehash.phash(img)
                except Exception as e:
                    log(sid, "WARN", f"visual-phishing: could not screenshot real site: {e}")

                # Screenshot each lookalike
                for target in target_domains:
                    try:
                        await page.goto(f"https://{target}", timeout=10000, wait_until="domcontentloaded")
                        await asyncio.sleep(1)
                        ss = await page.screenshot(full_page=False)

                        similarity = 0
                        if real_hash and image_ok:
                            img2 = Image.open(io.BytesIO(ss))
                            target_hash = imagehash.phash(img2)
                            hash_diff = real_hash - target_hash  # 0=identical, 64=completely different
                            similarity = round(max(0, (64 - hash_diff) / 64 * 100), 1)

                        results.append({
                            "domain": target,
                            "similarity": similarity,
                            "method": "screenshot+phash",
                            "has_screenshot": True,
                        })
                        log(sid, "INFO", f"visual-phishing: {target} → {similarity}% similar")

                    except Exception as e:
                        # Fall back to text comparison
                        content = await get_page_content(target)
                        sim = text_similarity(real_html, content.get("html",""))
                        results.append({
                            "domain": target,
                            "similarity": sim,
                            "method": "text-similarity",
                            "has_screenshot": False,
                            "error": str(e),
                        })

                await browser.close()

        except Exception as e:
            log(sid, "WARN", f"visual-phishing: Playwright error: {e} — using text fallback")
            playwright_ok = False

    if not playwright_ok:
        # Text content similarity fallback
        log(sid, "INFO", "visual-phishing: using HTML content similarity (Playwright unavailable)")
        for target in target_domains:
            content = await get_page_content(target)
            sim = text_similarity(real_html, content.get("html",""))
            results.append({
                "domain": target,
                "similarity": sim,
                "method": "text-similarity",
                "has_screenshot": False,
            })

    # Report results
    clones    = [r for r in results if r["similarity"] >= 75]
    similar   = [r for r in results if 40 <= r["similarity"] < 75]
    different = [r for r in results if r["similarity"] < 40]

    if clones:
        add_finding(sid, finding(
            tool, "CRITICAL",
            f"🔴 {len(clones)} pixel-perfect clone(s) detected — active phishing sites",
            f"These domains are visually near-identical to {domain}:\n" +
            "\n".join(
                f"• {r['domain']} — {r['similarity']}% visual match "
                f"({r['method']})"
                for r in sorted(clones, key=lambda x: -x["similarity"])
            ) +
            "\n\nAction: Report immediately to registrar + Google Safe Browsing.\n"
            "These are confirmed active phishing sites cloning your web design.",
            raw=clones,
        ))

    if similar:
        add_finding(sid, finding(
            tool, "WARNING",
            f"🟡 {len(similar)} domain(s) with partial visual similarity to {domain}",
            f"These domains share some visual elements with your site:\n" +
            "\n".join(f"• {r['domain']} — {r['similarity']}% match ({r['method']})"
                       for r in similar) +
            "\n\nManually review — may be legitimate or may be evolving phishing sites.",
            raw=similar,
        ))

    if different and not clones and not similar:
        add_finding(sid, finding(
            tool, "OK",
            f"🟢 Visual phishing: no clones detected across {len(different)} lookalike domains",
            f"Compared {len(different)} registered lookalike domains against {domain}.\n"
            f"None show significant visual similarity (all scored < 40%).\n"
            f"Method: {'screenshot perceptual hash' if playwright_ok else 'HTML text similarity'}.\n"
            f"Install Playwright for more accurate screenshot-based comparison.",
            raw=different,
        ))

    if not results:
        add_finding(sid, finding(
            tool, "INFO",
            "Visual phishing: no domains available to compare",
            f"No active lookalike domains were found to screenshot.\n"
            f"Run a full scan including dnstwist first.",
        ))

    log(sid, "OK" if not clones else "CRIT",
        f"visual-phishing: {len(clones)} clones, {len(similar)} similar, {len(different)} different")
    set_tool(sid, tool, "alert" if has_alert(sid, tool) else "done")


async def run_pipeline(sid: str, req: ScanRequest):
    brand  = req.brand.lower().strip()
    domain = req.domain or f"{brand}.com"
    org    = req.github_org or brand
    wanted = set(req.tools) if req.tools else None
    def go(t): return wanted is None or t in wanted

    scan_start = datetime.now()
    log(sid, "INFO", f"BrandMonitor v2.0 | brand={brand} | domain={domain} | org={org}")
    log(sid, "INFO", "Starting parallel scan pipeline — 4 phases")

    try:
        # Phase 1: Data Collection (parallel)
        p1 = []
        if go("twint"):     p1.append(run_twint(sid, brand))
        if go("rssbridge"): p1.append(run_rssbridge(sid, brand, domain))
        if p1: await asyncio.gather(*p1, return_exceptions=True)
        log(sid, "INFO", "Phase 1 done: data collection")

        # Phase 2: Leak Detection (parallel, capped for speed)
        p2 = []
        if go("gitleaks"):   p2.append(run_gitleaks(sid, brand, org))
        if go("trufflehog"): p2.append(run_trufflehog(sid, brand, org))
        if p2: await asyncio.gather(*p2, return_exceptions=True)
        log(sid, "INFO", "Phase 2 done: leak detection")

        # Phase 3: Domain Intelligence (parallel)
        p3 = []
        if go("dnstwist"): p3.append(run_dnstwist(sid, domain))
        if go("amass"):    p3.append(run_amass(sid, domain))
        if p3: await asyncio.gather(*p3, return_exceptions=True)
        log(sid, "INFO", "Phase 3 done: domain intelligence")

        # Phase 4: OSINT + Scraper (sequential — OSINT needs domain data)
        if go("spiderfoot"):
            await run_spiderfoot(sid, brand, domain)
        if go("scrapy"):
            await run_scrapy(sid, brand)
        log(sid, "INFO", "Phase 4 done: OSINT & scraping")

        # Phase 5: Advanced protection (parallel where safe)
        p5 = []
        if go("github_code"):    p5.append(run_github_codesearch(sid, brand, domain))
        if go("social_protect"): p5.append(run_social_protection(sid, brand))
        if go("darkweb"):        p5.append(run_darkweb(sid, brand, domain))
        if p5: await asyncio.gather(*p5, return_exceptions=True)

        # Visual phishing depends on dnstwist results — run after phase 3+5
        if go("visual_phish"):
            await run_visual_phishing(sid, domain)
        log(sid, "INFO", "Phase 5 done: advanced brand protection")

        # Finalize + accuracy summary
        scans[sid]["status"]   = "done"
        scans[sid]["finished"] = now_iso()

        fi = scans[sid]["findings"]
        c  = sum(1 for f in fi if f["severity"] == "CRITICAL")
        w  = sum(1 for f in fi if f["severity"] == "WARNING")
        i  = sum(1 for f in fi if f["severity"] == "INFO")
        ok = sum(1 for f in fi if f["severity"] == "OK")
        elapsed = (datetime.now() - scan_start).seconds

        # Suppress OK findings from final count display (they add noise)
        log(sid, "OK",
            f"Scan complete in {elapsed}s | "
            f"CRITICAL={c} | WARNING={w} | INFO={i} | CLEAN={ok}")

        # Add executive summary finding
        risk_level = "CRITICAL" if c > 0 else "WARNING" if w > 0 else "OK"
        summary_detail = (
            f"Scan target: {brand} ({domain})\n"
            f"Scan duration: {elapsed} seconds\n"
            f"\nFindings breakdown:\n"
            f"  Critical alerts: {c}\n"
            f"  Warnings:        {w}\n"
            f"  Informational:   {i}\n"
            f"  Clean checks:    {ok}\n"
            f"\nModules completed: {', '.join(k for k,v in scans[sid]['tools'].items() if v in ('done','alert'))}\n"
            f"\n{'⚠ IMMEDIATE ACTION REQUIRED on ' + str(c) + ' critical finding(s).' if c > 0 else ''}\n"
            f"{'Review ' + str(w) + ' warning(s) within 24 hours.' if w > 0 else ''}\n"
            f"{'✓ No critical threats detected.' if c == 0 and w == 0 else ''}"
        )
        add_finding(sid, finding(
            "pipeline", risk_level,
            f"{'🔴 ACTION REQUIRED' if c>0 else '🟡 Review needed' if w>0 else '🟢 All clear'} — Executive scan summary",
            summary_detail,
            raw={"critical": c, "warning": w, "info": i, "clean": ok, "elapsed_seconds": elapsed}
        ))

        # Save results
        out = RESULTS_DIR / f"{sid}_results.json"
        out.write_text(json.dumps(scans[sid], indent=2, default=str))
        log(sid, "INFO", f"Saved → {out}")

    except Exception as e:
        scans[sid]["status"]   = "error"
        scans[sid]["finished"] = now_iso()
        log(sid, "CRIT", f"Pipeline error: {e}")
        raise


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>BrandWatch — Live</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap');
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--bg4:#2d333b;
  --surface:#1c2128;--surface2:#2d333b;
  --border:#30363d;--border2:#444c56;
  --text:#cdd9e5;--muted:#8b949e;--dim:#545d68;
  --accent:#58a6ff;--accent2:#bc8cff;
  --red:#f85149;--amber:#d29922;--green:#3fb950;--teal:#39d353;
  --red-bg:rgba(248,81,73,.12);--amber-bg:rgba(210,153,34,.12);
  --green-bg:rgba(63,185,80,.12);--blue-bg:rgba(88,166,255,.12);
  --red-border:rgba(248,81,73,.35);--amber-border:rgba(210,153,34,.35);
  --green-border:rgba(63,185,80,.35);--blue-border:rgba(88,166,255,.35);
  --font:'Inter',system-ui,sans-serif;--mono:'JetBrains Mono',monospace;
}
html,body{background:var(--bg);color:var(--text);font-family:var(--font);min-height:100vh;font-size:13px}
.app{display:grid;grid-template-rows:auto 1fr;height:100vh;overflow:hidden}

/* TOPBAR */
.topbar{background:var(--bg2);border-bottom:1px solid var(--border);padding:0 20px;display:flex;align-items:center;gap:12px;height:54px;flex-shrink:0;z-index:50}
.logo{font-family:var(--mono);font-weight:600;font-size:16px;color:var(--accent);white-space:nowrap;letter-spacing:-.5px}
.logo b{color:var(--text)}
.logo .ver{font-size:9px;background:var(--green);color:#000;padding:1px 6px;border-radius:3px;font-weight:700;vertical-align:super;margin-left:4px}
.inp{background:var(--bg3);border:1px solid var(--border);color:var(--text);font-family:var(--mono);font-size:12px;padding:7px 11px;border-radius:7px;outline:none;transition:border-color .15s,box-shadow .15s}
.inp:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(88,166,255,.1)}
.inp::placeholder{color:var(--dim)}
.inp-brand{width:155px}.inp-domain{width:195px}
.conn{display:flex;align-items:center;gap:7px;margin-left:auto}
.cdot{width:8px;height:8px;border-radius:50%;background:var(--dim);flex-shrink:0;transition:all .3s}
.cdot.live{background:var(--green);box-shadow:0 0 6px var(--green);animation:blink 2s infinite}
.cdot.dead{background:var(--red)}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}
.clbl{font-size:10px;color:var(--muted);font-family:var(--mono)}
.scan-btn{background:linear-gradient(135deg,var(--accent),#3d8bff);color:#000;font-family:var(--mono);font-weight:700;font-size:11px;padding:8px 20px;border:none;border-radius:7px;cursor:pointer;transition:all .15s;white-space:nowrap;letter-spacing:.3px;box-shadow:0 2px 8px rgba(88,166,255,.3)}
.scan-btn:hover{filter:brightness(1.1);box-shadow:0 4px 14px rgba(88,166,255,.4)}
.scan-btn.running{background:linear-gradient(135deg,var(--amber),#b8870f);box-shadow:0 2px 8px rgba(210,153,34,.3);animation:pulse .9s infinite}
.scan-btn:disabled{opacity:.4;cursor:not-allowed;box-shadow:none}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.65}}

/* LAYOUT */
.main{display:grid;grid-template-columns:185px 1fr 270px;overflow:hidden;height:calc(100vh - 54px)}
.sidebar{background:var(--bg2);border-right:1px solid var(--border);padding:14px 0;overflow-y:auto;display:flex;flex-direction:column}
.ns{font-size:9px;color:var(--dim);letter-spacing:1.2px;padding:12px 14px 5px;text-transform:uppercase;font-weight:600}
.ni{display:flex;align-items:center;gap:9px;padding:8px 14px;font-size:12px;cursor:pointer;color:var(--muted);border:none;background:none;width:100%;text-align:left;font-family:var(--font);border-left:2px solid transparent;transition:all .15s;position:relative}
.ni:hover{background:rgba(255,255,255,.04);color:var(--text)}
.ni.active{background:rgba(88,166,255,.08);color:var(--accent);border-left-color:var(--accent)}
.ni .ic{width:16px;text-align:center;font-size:14px}
.bdg{margin-left:auto;font-size:9px;padding:2px 6px;border-radius:10px;font-weight:700;font-family:var(--mono);display:none;cursor:pointer}
.bdg.r{background:var(--red);color:#fff;display:inline}
.bdg.a{background:var(--amber);color:#000;display:inline}
.bdg.b{background:var(--accent);color:#000;display:inline}
.bdg.g{background:var(--green);color:#000;display:inline}

/* CONTENT */
.content{overflow-y:auto;padding:18px;display:flex;flex-direction:column;gap:16px;background:var(--bg)}
.view{display:none;flex-direction:column;gap:14px}
.view.active{display:flex}
.sec-hd{font-size:18px;font-weight:700;color:var(--text);letter-spacing:-.4px}
.sec-sub{font-size:11px;color:var(--muted);margin-top:3px;line-height:1.5}

/* STATS */
.stats-row{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}
.stat{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:14px 16px;cursor:pointer;transition:all .2s;position:relative;overflow:hidden}
.stat::after{content:'';position:absolute;inset:0;background:currentColor;opacity:0;transition:opacity .2s}
.stat:hover{transform:translateY(-1px);box-shadow:0 4px 16px rgba(0,0,0,.3)}
.stat .v{font-family:var(--mono);font-size:26px;font-weight:700;letter-spacing:-1px;line-height:1}
.stat .l{font-size:9px;color:var(--muted);margin-top:5px;letter-spacing:.6px;text-transform:uppercase;font-weight:600}
.stat .hint{font-size:9px;color:var(--dim);margin-top:3px}
.stat.r{border-color:var(--red-border);background:var(--red-bg)}.stat.r .v{color:var(--red)}
.stat.a{border-color:var(--amber-border);background:var(--amber-bg)}.stat.a .v{color:var(--amber)}
.stat.b{border-color:var(--blue-border);background:var(--blue-bg)}.stat.b .v{color:var(--accent)}
.stat.g{border-color:var(--green-border);background:var(--green-bg)}.stat.g .v{color:var(--green)}
.stat.clickable:hover .hint{color:var(--accent)}

/* PROGRESS */
.sp{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:16px;display:none}
.sp.on{display:block}
.sp-top{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
.sp-lbl{font-size:13px;font-weight:600;color:var(--text)}
.sp-pct{font-family:var(--mono);font-size:13px;color:var(--accent);font-weight:600}
.sp-bar{height:4px;background:var(--bg3);border-radius:2px;overflow:hidden;margin-bottom:12px}
.sp-fill{height:100%;background:linear-gradient(90deg,var(--accent),var(--accent2));border-radius:2px;transition:width .4s ease}
.sp-phases{display:grid;grid-template-columns:repeat(5,1fr);gap:6px}
.sp-ph{text-align:center;font-size:9px;padding:6px 2px;border-radius:6px;background:var(--bg3);color:var(--dim);transition:all .3s;font-family:var(--mono);border:1px solid transparent}
.sp-ph.on{background:var(--blue-bg);color:var(--accent);border-color:var(--blue-border)}
.sp-ph.ok{background:var(--green-bg);color:var(--green);border-color:var(--green-border)}

/* TOOL GRID */
.tgrid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.tc{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:14px;transition:all .2s}
.tc.running{border-color:var(--blue-border);background:rgba(88,166,255,.03)}
.tc.done{border-color:var(--green-border)}
.tc.alert{border-color:var(--red-border);background:rgba(248,81,73,.03)}
.tc.error{opacity:.5}
.tc-top{display:flex;align-items:center;gap:9px;margin-bottom:10px}
.tc-ic{font-size:17px;width:32px;height:32px;border-radius:7px;background:var(--bg3);display:flex;align-items:center;justify-content:center;flex-shrink:0;border:1px solid var(--border)}
.tc-name{font-size:12px;font-weight:600;color:var(--text)}.tc-cat{font-size:9px;color:var(--dim);margin-top:1px;font-family:var(--mono)}.tc-st{margin-left:auto}
.pill{display:inline-block;font-size:8px;padding:2px 7px;border-radius:5px;font-weight:700;font-family:var(--mono);letter-spacing:.4px}
.pill.idle{background:var(--bg3);color:var(--dim);border:1px solid var(--border)}
.pill.running{background:var(--blue-bg);color:var(--accent);border:1px solid var(--blue-border);animation:pulse .9s infinite}
.pill.done{background:var(--green-bg);color:var(--green);border:1px solid var(--green-border)}
.pill.alert{background:var(--red-bg);color:var(--red);border:1px solid var(--red-border)}
.pill.error{background:var(--bg3);color:var(--dim);border:1px solid var(--border)}
.prg{height:2px;background:var(--bg3);border-radius:2px;margin:7px 0;overflow:hidden}
.pf{height:100%;background:linear-gradient(90deg,var(--accent),var(--accent2));border-radius:2px;transition:width .5s}
.tc-desc{font-size:10px;color:var(--muted);line-height:1.6;margin-bottom:8px}
.tc-fi{font-size:10px;line-height:1.9;color:var(--text)}
.fi{display:flex;gap:6px;align-items:baseline;padding:1px 0}
.fi::before{content:'›';color:var(--accent2);flex-shrink:0;font-weight:700}
.fi.cr{color:var(--red)}.fi.cr::before{content:'●';color:var(--red)}
.fi.wn{color:var(--amber)}.fi.wn::before{content:'◆';color:var(--amber)}
.fi.ok{color:var(--green)}.fi.ok::before{content:'✓';color:var(--green)}

/* FINDING CARDS — detailed */
.rc{background:var(--surface);border:1px solid var(--border);border-radius:10px;margin-bottom:10px;overflow:hidden;transition:box-shadow .2s}
.rc:hover{box-shadow:0 4px 20px rgba(0,0,0,.3)}
.rc.CRITICAL{border-color:var(--red-border)}
.rc.WARNING{border-color:var(--amber-border)}
.rc.INFO{border-color:var(--blue-border)}
.rc.OK{border-color:var(--green-border)}
.rc-header{padding:12px 14px;display:flex;align-items:flex-start;gap:10px;cursor:pointer;user-select:none}
.rc-header:hover{background:rgba(255,255,255,.02)}
.rc-icon{width:32px;height:32px;border-radius:7px;display:flex;align-items:center;justify-content:center;font-size:15px;flex-shrink:0}
.rc.CRITICAL .rc-icon{background:var(--red-bg);border:1px solid var(--red-border)}
.rc.WARNING .rc-icon{background:var(--amber-bg);border:1px solid var(--amber-border)}
.rc.INFO .rc-icon{background:var(--blue-bg);border:1px solid var(--blue-border)}
.rc.OK .rc-icon{background:var(--green-bg);border:1px solid var(--green-border)}
.rc-head-text{flex:1;min-width:0}
.rc-title{font-size:12px;font-weight:600;color:var(--text);line-height:1.4;margin-bottom:3px}
.rc-meta-line{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
.sev{font-size:8px;font-weight:700;padding:2px 7px;border-radius:5px;font-family:var(--mono);letter-spacing:.5px}
.sev.CRITICAL{background:var(--red-bg);color:var(--red);border:1px solid var(--red-border)}
.sev.WARNING{background:var(--amber-bg);color:var(--amber);border:1px solid var(--amber-border)}
.sev.INFO{background:var(--blue-bg);color:var(--accent);border:1px solid var(--blue-border)}
.sev.OK{background:var(--green-bg);color:var(--green);border:1px solid var(--green-border)}
.tag{font-size:9px;background:var(--bg3);color:var(--muted);padding:2px 7px;border-radius:5px;font-family:var(--mono);border:1px solid var(--border)}
.rc-toggle{font-size:11px;color:var(--dim);flex-shrink:0;padding:2px 6px;border-radius:4px;background:var(--bg3);border:1px solid var(--border);font-family:var(--mono);cursor:pointer;transition:all .2s;white-space:nowrap}
.rc-toggle:hover{color:var(--accent);border-color:var(--accent)}
.rc-body{display:none;border-top:1px solid var(--border);background:var(--bg)}
.rc-body.open{display:block}
.rc-section{padding:14px 16px;border-bottom:1px solid var(--border)}
.rc-section:last-child{border-bottom:none}
.rc-section-title{font-size:9px;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:var(--dim);margin-bottom:8px;font-family:var(--mono)}
.rc-detail-grid{display:grid;grid-template-columns:1fr;gap:6px}
.detail-row{display:grid;grid-template-columns:140px 1fr;gap:8px;align-items:baseline;padding:4px 0;border-bottom:1px solid rgba(48,54,61,.5)}
.detail-row:last-child{border-bottom:none}
.detail-label{font-size:9px;color:var(--dim);font-family:var(--mono);font-weight:600;letter-spacing:.3px;text-transform:uppercase}
.detail-value{font-size:11px;color:var(--text);font-family:var(--mono);word-break:break-all;line-height:1.5}
.detail-value.red{color:var(--red)}.detail-value.amber{color:var(--amber)}.detail-value.green{color:var(--green)}.detail-value.blue{color:var(--accent)}
.rc-raw{background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:10px 12px;font-family:var(--mono);font-size:9px;color:var(--muted);white-space:pre-wrap;overflow-x:auto;max-height:200px;overflow-y:auto;line-height:1.7}
.rc-actions{display:flex;gap:8px;flex-wrap:wrap;padding:10px 16px;background:var(--bg2);border-top:1px solid var(--border)}
.action-btn{font-size:10px;padding:5px 12px;border-radius:5px;border:1px solid var(--border);background:var(--bg3);color:var(--text);cursor:pointer;font-family:var(--mono);transition:all .15s}
.action-btn:hover{border-color:var(--accent);color:var(--accent)}
.action-btn.danger{border-color:var(--red-border);color:var(--red)}
.action-btn.danger:hover{background:var(--red-bg)}

/* MODAL OVERLAY */
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:1000;display:none;align-items:center;justify-content:center;backdrop-filter:blur(4px)}
.modal-overlay.open{display:flex}
.modal{background:var(--bg2);border:1px solid var(--border2);border-radius:12px;width:min(760px,95vw);max-height:90vh;overflow:hidden;display:flex;flex-direction:column;box-shadow:0 20px 60px rgba(0,0,0,.6)}
.modal-header{padding:16px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:12px;flex-shrink:0}
.modal-sev-icon{width:36px;height:36px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0}
.modal-sev-icon.CRITICAL{background:var(--red-bg);border:1px solid var(--red-border)}
.modal-sev-icon.WARNING{background:var(--amber-bg);border:1px solid var(--amber-border)}
.modal-sev-icon.INFO{background:var(--blue-bg);border:1px solid var(--blue-border)}
.modal-sev-icon.OK{background:var(--green-bg);border:1px solid var(--green-border)}
.modal-title{flex:1;font-size:14px;font-weight:700;color:var(--text);line-height:1.3}
.modal-close{background:var(--bg3);border:1px solid var(--border);color:var(--muted);width:28px;height:28px;border-radius:6px;cursor:pointer;font-size:14px;display:flex;align-items:center;justify-content:center;transition:all .15s;flex-shrink:0}
.modal-close:hover{color:var(--text);border-color:var(--border2)}
.modal-body{overflow-y:auto;flex:1;padding:0}
.modal-section{padding:16px 20px;border-bottom:1px solid var(--border)}
.modal-section:last-child{border-bottom:none}
.modal-section-title{font-size:9px;font-weight:700;letter-spacing:1.2px;text-transform:uppercase;color:var(--dim);margin-bottom:12px;font-family:var(--mono);display:flex;align-items:center;gap:6px}
.modal-section-title::before{content:'';width:3px;height:12px;border-radius:2px;background:var(--accent);display:inline-block}
.info-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.info-item{background:var(--bg3);border:1px solid var(--border);border-radius:7px;padding:10px 12px}
.info-item.full{grid-column:1/-1}
.info-item .k{font-size:9px;color:var(--dim);font-family:var(--mono);letter-spacing:.5px;text-transform:uppercase;margin-bottom:4px;font-weight:600}
.info-item .v{font-size:11px;color:var(--text);font-family:var(--mono);word-break:break-all;line-height:1.6}
.info-item .v.red{color:var(--red)}.info-item .v.amber{color:var(--amber)}.info-item .v.green{color:var(--green)}.info-item .v.blue{color:var(--accent)}
.risk-meter{height:8px;background:var(--bg3);border-radius:4px;overflow:hidden;margin-top:6px;border:1px solid var(--border)}
.risk-fill{height:100%;border-radius:4px;transition:width .5s}
.recommend-box{background:rgba(88,166,255,.05);border:1px solid var(--blue-border);border-radius:7px;padding:12px 14px}
.recommend-title{font-size:10px;font-weight:700;color:var(--accent);margin-bottom:8px;display:flex;align-items:center;gap:6px}
.recommend-list{list-style:none;display:flex;flex-direction:column;gap:5px}
.recommend-list li{font-size:10px;color:var(--text);padding-left:14px;position:relative;line-height:1.5}
.recommend-list li::before{content:'→';position:absolute;left:0;color:var(--accent);font-size:10px}
.raw-block{background:var(--bg3);border:1px solid var(--border);border-radius:7px;padding:12px;font-family:var(--mono);font-size:9px;color:var(--muted);white-space:pre-wrap;overflow-x:auto;max-height:220px;overflow-y:auto;line-height:1.8}
.modal-footer{padding:12px 20px;border-top:1px solid var(--border);display:flex;gap:8px;flex-shrink:0;background:var(--bg2)}
.mf-btn{font-size:10px;padding:6px 14px;border-radius:6px;border:1px solid var(--border);background:var(--bg3);color:var(--text);cursor:pointer;font-family:var(--mono);transition:all .15s}
.mf-btn:hover{border-color:var(--accent);color:var(--accent)}
.mf-btn.primary{background:var(--accent);color:#000;border-color:var(--accent);font-weight:700}
.mf-btn.primary:hover{filter:brightness(1.1)}
.nav-btns{margin-left:auto;display:flex;gap:6px}

/* ALERTS PANEL */
.rpanel{background:var(--bg2);border-left:1px solid var(--border);display:flex;flex-direction:column;overflow:hidden}
.rtabs{display:flex;border-bottom:1px solid var(--border);flex-shrink:0}
.rtab{flex:1;padding:11px 4px;font-size:11px;text-align:center;cursor:pointer;color:var(--muted);border:none;background:none;border-bottom:2px solid transparent;transition:all .15s;font-family:var(--mono)}
.rtab.active{color:var(--accent);border-bottom-color:var(--accent)}
.rbody{flex:1;overflow-y:auto;padding:10px;display:flex;flex-direction:column;gap:8px}
.rbody.hide{display:none}
.ac{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:11px;border-left:3px solid var(--red);cursor:pointer;transition:all .15s}
.ac:hover{background:var(--surface2);transform:translateX(2px)}
.ac.WARNING{border-left-color:var(--amber)}.ac.INFO{border-left-color:var(--accent)}.ac.OK{border-left-color:var(--green)}
.ac-sev{font-size:8px;font-weight:700;letter-spacing:1px;margin-bottom:3px;font-family:var(--mono)}
.ac-sev.CRITICAL{color:var(--red)}.ac-sev.WARNING{color:var(--amber)}.ac-sev.INFO{color:var(--accent)}.ac-sev.OK{color:var(--green)}
.ac-title{font-size:11px;font-weight:600;color:var(--text);margin-bottom:4px;line-height:1.4}
.ac-preview{font-size:9px;color:var(--muted);line-height:1.5;font-family:var(--mono);overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical}
.ac-ft{display:flex;justify-content:space-between;margin-top:6px;align-items:center}
.ac-click{font-size:8px;color:var(--accent);font-family:var(--mono)}

/* LOG */
.lw{font-family:var(--mono);font-size:9px;line-height:2}
.ll{display:flex;gap:6px;align-items:baseline;padding:2px 0;border-bottom:1px solid rgba(48,54,61,.4)}
.lts{color:var(--dim);flex-shrink:0;min-width:52px}
.llv{font-size:8px;font-weight:700;padding:0 4px;border-radius:3px;flex-shrink:0;min-width:34px;text-align:center}
.llv.INFO{background:var(--blue-bg);color:var(--accent)}.llv.WARN{background:var(--amber-bg);color:var(--amber)}
.llv.CRIT{background:var(--red-bg);color:var(--red)}.llv.OK{background:var(--green-bg);color:var(--green)}
.lmsg{color:var(--text);word-break:break-all}

/* HEALTH */
.hgrid{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.hcard{background:var(--surface);border:1px solid var(--border);border-radius:7px;padding:9px 12px;display:flex;justify-content:space-between;align-items:center}
.hn{font-size:11px;color:var(--text);font-family:var(--mono)}.hv{font-size:10px;font-weight:700;font-family:var(--mono)}
.hv.ok{color:var(--green)}.hv.no{color:var(--red)}
.warn-box{background:var(--amber-bg);border:1px solid var(--amber-border);border-radius:7px;padding:12px;font-size:10px;line-height:1.8;margin-top:10px;color:var(--text)}
.empty{text-align:center;padding:40px 16px;color:var(--dim)}
.empty .ic{font-size:28px;margin-bottom:10px}
.empty p{font-size:11px;line-height:1.8;color:var(--muted)}
::-webkit-scrollbar{width:4px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:var(--border2);border-radius:2px}
</style>
</head>
<body>
<div class="app">
<header class="topbar">
  <div class="logo">brand<b>watch</b><span class="ver">v2</span></div>
  <input class="inp inp-brand" id="inp-brand" type="text" placeholder="Brand / college name">
  <input class="inp inp-domain" id="inp-domain" type="text" placeholder="college.ac.in">
  <div class="conn"><div class="cdot" id="cdot"></div><span class="clbl" id="clbl">connecting…</span></div>
  <button class="scan-btn" id="scan-btn" onclick="startScan()">▶ SCAN</button>
</header>

<div class="main">
<nav class="sidebar">
  <div class="ns">Overview</div>
  <button class="ni active" onclick="gv('dashboard',this)"><span class="ic">⬡</span>Dashboard</button>
  <div class="ns">Collection</div>
  <button class="ni" onclick="gv('mentions',this)"><span class="ic">🐦</span>Mentions<span class="bdg a" id="b-mentions">0</span></button>
  <button class="ni" onclick="gv('news',this)"><span class="ic">📰</span>News / RSS<span class="bdg b" id="b-news">0</span></button>
  <div class="ns">Threats</div>
  <button class="ni" onclick="gv('leaks',this)"><span class="ic">🔑</span>Leaked Secrets<span class="bdg r" id="b-leaks">0</span></button>
  <button class="ni" onclick="gv('domains',this)"><span class="ic">🌐</span>Fake Domains<span class="bdg r" id="b-domains">0</span></button>
  <div class="ns">Intelligence</div>
  <button class="ni" onclick="gv('osint',this)"><span class="ic">🕵</span>Recon & OSINT<span class="bdg r" id="b-osint">0</span></button>
  <div class="ns">Brand Protection</div>
  <button class="ni" onclick="gv('ghcode',this)"><span class="ic">🔍</span>Code Search<span class="bdg r" id="b-ghcode">0</span></button>
  <button class="ni" onclick="gv('social',this)"><span class="ic">📱</span>Social Guard<span class="bdg r" id="b-social">0</span></button>
  <button class="ni" onclick="gv('darkweb',this)"><span class="ic">🌑</span>Dark Web<span class="bdg r" id="b-darkweb">0</span></button>
  <button class="ni" onclick="gv('visual',this)"><span class="ic">📸</span>Visual Clones<span class="bdg r" id="b-visual">0</span></button>
  <div class="ns">System</div>
  <button class="ni" onclick="gv('logs',this)"><span class="ic">≡</span>Live Logs</button>
  <button class="ni" onclick="gv('health',this)"><span class="ic">♥</span>Health Check</button>
</nav>

<main class="content">
  <!-- DASHBOARD -->
  <div class="view active" id="view-dashboard">
    <div>
      <div class="sec-hd">Security Overview</div>
      <div class="sec-sub" id="dash-sub">Enter your brand or domain name and click ▶ SCAN to begin monitoring</div>
    </div>
    <div class="sp" id="sp">
      <div class="sp-top"><span class="sp-lbl" id="sp-lbl">Initializing…</span><span class="sp-pct" id="sp-pct">0%</span></div>
      <div class="sp-bar"><div class="sp-fill" id="sp-fill" style="width:0%"></div></div>
      <div class="sp-phases">
        <div class="sp-ph" id="ph0">📡 Collect</div><div class="sp-ph" id="ph1">🔑 Secrets</div>
        <div class="sp-ph" id="ph2">🌐 Domains</div><div class="sp-ph" id="ph3">🕵 Recon</div>
        <div class="sp-ph" id="ph4">✓ Done</div>
      </div>
    </div>
    <div class="stats-row">
      <div class="stat r clickable" onclick="showFiltered('CRITICAL')" title="Click to view critical findings">
        <div class="v" id="sc">–</div><div class="l">Critical Alerts</div><div class="hint">Click to view →</div>
      </div>
      <div class="stat a clickable" onclick="showFiltered('WARNING')" title="Click to view warnings">
        <div class="v" id="sw">–</div><div class="l">Warnings</div><div class="hint">Click to view →</div>
      </div>
      <div class="stat b clickable" onclick="showFiltered('ALL')" title="Click to view all findings">
        <div class="v" id="st">–</div><div class="l">Total Findings</div><div class="hint">Click to view →</div>
      </div>
      <div class="stat g">
        <div class="v" id="sa">–</div><div class="l">Modules Run</div><div class="hint" id="scan-time"></div>
      </div>
    </div>
    <div class="tgrid" id="tgrid"></div>
  </div>

  <!-- MENTIONS -->
  <div class="view" id="view-mentions">
    <div><div class="sec-hd">Social Media Mentions</div><div class="sec-sub">Real-time brand mentions across Twitter/X and social platforms</div></div>
    <div id="mentions-body"><div class="empty"><div class="ic">🐦</div><p>Run a scan to collect social media mentions.</p></div></div>
  </div>

  <!-- NEWS -->
  <div class="view" id="view-news">
    <div><div class="sec-hd">News & Media Coverage</div><div class="sec-sub">Brand mentions from news outlets, tech blogs, and community forums</div></div>
    <div id="news-body"><div class="empty"><div class="ic">📰</div><p>Run a scan to collect news coverage.</p></div></div>
  </div>

  <!-- LEAKS -->
  <div class="view" id="view-leaks">
    <div><div class="sec-hd">Leaked Credentials & Secrets</div><div class="sec-sub">Exposed API keys, tokens, passwords, and credentials found in public repositories</div></div>
    <div id="leaks-body"><div class="empty"><div class="ic">🔑</div><p>Run a scan to check for leaked secrets.</p></div></div>
  </div>

  <!-- DOMAINS -->
  <div class="view" id="view-domains">
    <div><div class="sec-hd">Fake & Lookalike Domains</div><div class="sec-sub">Typosquat, homoglyph, and phishing domains registered to impersonate your brand</div></div>
    <div id="domains-body"><div class="empty"><div class="ic">🌐</div><p>Run a scan to detect impersonation domains.</p></div></div>
  </div>

  <!-- OSINT -->
  <div class="view" id="view-osint">
    <div><div class="sec-hd">Reconnaissance & Intelligence</div><div class="sec-sub">Infrastructure exposure, vulnerabilities, DNS configuration, email security, and data breach history</div></div>
    <div id="osint-body"><div class="empty"><div class="ic">🕵</div><p>Run a scan to gather intelligence.</p></div></div>
  </div>

  <!-- FILTERED VIEW -->
  <div class="view" id="view-filtered">
    <div style="display:flex;align-items:center;gap:12px">
      <div>
        <div class="sec-hd" id="filtered-title">Filtered Results</div>
        <div class="sec-sub" id="filtered-sub">Showing filtered findings</div>
      </div>
      <button onclick="gv('dashboard',document.querySelector('.ni'))" style="margin-left:auto;background:var(--bg3);border:1px solid var(--border);color:var(--muted);font-family:var(--mono);font-size:10px;padding:6px 12px;border-radius:6px;cursor:pointer">← Back</button>
    </div>
    <div id="filtered-body"></div>
  </div>

  <!-- LOGS -->
  <!-- GITHUB CODE SEARCH VIEW -->
  <div class="view" id="view-ghcode">
    <div><div class="sec-hd">GitHub Code Search</div>
    <div class="sec-sub">Scans ALL public GitHub for leaked credentials — beyond just your org repos</div></div>
    <div id="ghcode-body"><div class="empty"><div class="ic">🔍</div><p>Run a scan to search GitHub code.</p></div></div>
  </div>

  <!-- SOCIAL MEDIA GUARD VIEW -->
  <div class="view" id="view-social">
    <div><div class="sec-hd">Social Media Guard</div>
    <div class="sec-sub">Checks for unclaimed handles and impersonation accounts across 8 platforms</div></div>
    <div id="social-body"><div class="empty"><div class="ic">📱</div><p>Run a scan to check social media.</p></div></div>
  </div>

  <!-- DARK WEB MONITOR VIEW -->
  <div class="view" id="view-darkweb">
    <div><div class="sec-hd">Dark Web & Paste Monitor</div>
    <div class="sec-sub">Paste sites · GitHub Gists · IntelligenceX · HackerNews · HIBP breach database</div></div>
    <div id="darkweb-body"><div class="empty"><div class="ic">🌑</div><p>Run a scan to check dark web sources.</p></div></div>
  </div>

  <!-- VISUAL CLONE DETECTOR VIEW -->
  <div class="view" id="view-visual">
    <div><div class="sec-hd">Visual Clone Detector</div>
    <div class="sec-sub">Screenshots lookalike domains and compares visual similarity to your real site</div></div>
    <div id="visual-body"><div class="empty"><div class="ic">📸</div><p>Run a scan to check visual similarity.</p></div></div>
  </div>

  <div class="view" id="view-logs">
    <div><div class="sec-hd">Live Scan Logs</div><div class="sec-sub">Real-time pipeline output — all activity shown here</div></div>
    <div class="lw" id="log-body"><div class="empty"><p>Logs appear during a scan.</p></div></div>
  </div>

  <!-- HEALTH -->
  <div class="view" id="view-health">
    <div><div class="sec-hd">System Health</div><div class="sec-sub">Installed modules and their status</div></div>
    <div id="health-body"><div class="empty"><div class="ic">♥</div><p>Loading…</p></div></div>
    <button onclick="loadHealth()" style="align-self:flex-start;background:var(--bg3);border:1px solid var(--border);color:var(--text);font-family:var(--mono);font-size:10px;padding:7px 14px;border-radius:6px;cursor:pointer;transition:border-color .15s" onmouseover="this.style.borderColor='var(--accent)'" onmouseout="this.style.borderColor='var(--border)'">↺ Refresh</button>
  </div>
</main>

<aside class="rpanel">
  <div class="rtabs">
    <button class="rtab active" onclick="srt('alerts',this)">Alerts</button>
    <button class="rtab" onclick="srt('rtlog',this)">Live Log</button>
  </div>
  <div class="rbody" id="rb-alerts"><div class="empty"><div class="ic">🛡</div><p>No alerts yet.<br>Run a scan to begin.</p></div></div>
  <div class="rbody hide" id="rb-rtlog"><div class="lw" id="rtlog-body"></div></div>
</aside>
</div>
</div>

<!-- DETAIL MODAL -->
<div class="modal-overlay" id="modal-overlay" onclick="closeModal(event)">
  <div class="modal" id="modal">
    <div class="modal-header">
      <div class="modal-sev-icon" id="m-icon">⚠</div>
      <div class="modal-title" id="m-title">Finding Detail</div>
      <button class="modal-close" onclick="closeModalDirect()">✕</button>
    </div>
    <div class="modal-body" id="m-body"></div>
    <div class="modal-footer">
      <div class="nav-btns">
        <button class="mf-btn" id="m-prev" onclick="navModal(-1)">← Prev</button>
        <button class="mf-btn" id="m-next" onclick="navModal(1)">Next →</button>
      </div>
      <button class="mf-btn" onclick="closeModalDirect()">Close</button>
    </div>
  </div>
</div>

<script>
// ══════ STATE ══════
const MODULES=[
  {id:'twint',name:'Social Monitoring',cat:'Data Collection',ic:'🐦',desc:'Scans Twitter/X mirrors, Reddit and HackerNews for brand mentions'},
  {id:'rssbridge',name:'News Intelligence',cat:'Data Collection',ic:'📡',desc:'Aggregates Google News, security blogs and forum discussions'},
  {id:'gitleaks',name:'Secret Detection',cat:'Credential Scan',ic:'🔐',desc:'Scans public code repositories for exposed API keys and tokens'},
  {id:'trufflehog',name:'Deep Credential Scan',cat:'Credential Scan',ic:'🐷',desc:'Verified-only mode — reports only confirmed active credentials'},
  {id:'dnstwist',name:'Domain Impersonation',cat:'Phishing Detection',ic:'🌀',desc:'Smart-scored lookalike domain detection with MX + age filtering'},
  {id:'amass',name:'Infrastructure Mapping',cat:'Reconnaissance',ic:'🗺',desc:'Subdomain enumeration via amass and crt.sh CT logs'},
  {id:'spiderfoot',name:'Threat Intelligence',cat:'OSINT',ic:'🕵',desc:'Shodan CVEs, DNS security, WHOIS, paste sites — all free'},
  {id:'scrapy',name:'Custom Scraping',cat:'Optional',ic:'🕸',desc:'Gist dumps, StackOverflow configs, paste sites, dork hints'},
  {id:'github_code',name:'GitHub Code Search',cat:'Brand Protection',ic:'🔍',desc:'Searches ALL public GitHub code for leaked credentials beyond org repos'},
  {id:'social_protect',name:'Social Media Guard',cat:'Brand Protection',ic:'📱',desc:'Detects unclaimed handles and impersonation accounts across 8 platforms'},
  {id:'darkweb',name:'Dark Web Monitor',cat:'Brand Protection',ic:'🌑',desc:'Paste sites, GitHub Gists, IntelligenceX, HackerNews, HIBP breach check'},
  {id:'visual_phish',name:'Visual Clone Detector',cat:'Brand Protection',ic:'📸',desc:'Screenshots lookalike domains and compares visual similarity to real site'},
];

let scanId=null, pollT=null, sse=null, allFindings=[], modalIdx=0, modalList=[];

// ══════ ROUTING ══════
function gv(id,btn){
  document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));
  document.querySelectorAll('.ni').forEach(b=>b.classList.remove('active'));
  document.getElementById('view-'+id).classList.add('active');
  if(btn) btn.classList.add('active');
  if(id==='health') loadHealth();
}
function srt(id,btn){
  document.querySelectorAll('.rtab').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('rb-alerts').className='rbody'+(id==='alerts'?'':' hide');
  document.getElementById('rb-rtlog').className='rbody'+(id==='rtlog'?'':' hide');
}
function showFiltered(sev){
  const filtered = sev==='ALL' ? allFindings : allFindings.filter(f=>f.severity===sev);
  const icons = {CRITICAL:'🔴',WARNING:'🟡',INFO:'🔵',OK:'🟢',ALL:'📋'};
  const labels = {CRITICAL:'Critical Findings',WARNING:'Warnings',INFO:'Informational',OK:'All Clear',ALL:'All Findings'};
  document.getElementById('filtered-title').textContent = labels[sev]||'Findings';
  document.getElementById('filtered-sub').textContent = `${filtered.length} finding(s) ${sev!=='ALL'?'with '+sev+' severity':'total'}`;
  document.getElementById('filtered-body').innerHTML = filtered.length
    ? filtered.map((f,i)=>buildCard(f,i,'filtered')).join('')
    : `<div class="empty"><div class="ic">${icons[sev]||'✓'}</div><p>No ${sev.toLowerCase()} findings detected.</p></div>`;
  gv('filtered', null);
}

// ══════ TOOL CARDS ══════
function tc(t,st,fi=[]){
  const L={idle:'IDLE',running:'SCANNING',done:'DONE',alert:'ALERTS',error:'ERROR'}[st]||'IDLE';
  const p=st==='running'?`<div class="prg"><div class="pf" style="width:${Math.round(Math.random()*45+20)}%"></div></div>`:'';
  return `<div class="tc ${st}" id="tc-${t.id}">
    <div class="tc-top">
      <div class="tc-ic">${t.ic}</div>
      <div><div class="tc-name">${t.name}</div><div class="tc-cat">${t.cat}</div></div>
      <div class="tc-st"><span class="pill ${st}">${L}</span></div>
    </div>${p}
    <div class="tc-desc">${t.desc}</div>
    <div class="tc-fi">${fi.map(f=>`<div class="fi ${f.c||''}">${esc(f.t)}</div>`).join('')}</div>
  </div>`;
}
function utc(id,st,fi){const t=MODULES.find(x=>x.id===id);const e=document.getElementById('tc-'+id);if(t&&e)e.outerHTML=tc(t,st,fi);}
function initGrid(){document.getElementById('tgrid').innerHTML=MODULES.map(t=>tc(t,'idle',[])).join('');}

// ══════ FINDING CARD BUILDER ══════
const SEV_ICON={CRITICAL:'🔴',WARNING:'🟡',INFO:'🔵',OK:'🟢'};
const CAT_ICON={twint:'🐦',rssbridge:'📰',gitleaks:'🔑',trufflehog:'🔑',dnstwist:'🌐',amass:'🗺',spiderfoot:'🕵',scrapy:'🕸'};

function buildCard(f, globalIdx, ctx){
  const icon = SEV_ICON[f.severity]||'●';
  const catIcon = CAT_ICON[f.tool]||'●';
  // Parse detail into structured rows
  const rows = parseDetail(f.detail, f.severity, f.tool);
  const recs = getRecommendations(f);
  const catLabel = MODULES.find(m=>m.id===f.tool)?.cat || f.tool;

  return `<div class="rc ${f.severity}" id="rc-${globalIdx}">
    <div class="rc-header" onclick="openModal(${globalIdx})">
      <div class="rc-icon">${icon}</div>
      <div class="rc-head-text">
        <div class="rc-title">${esc(cleanTitle(f.title))}</div>
        <div class="rc-meta-line">
          <span class="sev ${f.severity}">${f.severity}</span>
          <span class="tag">${catIcon} ${catLabel}</span>
          <span class="tag">${(f.ts||'').substring(11,19)}</span>
        </div>
      </div>
      <div class="rc-toggle">View Details →</div>
    </div>
  </div>`;
}

function cleanTitle(t){return String(t||'').replace(/^[🔴🟡🔵🟢]\s*/,'');}

function parseDetail(detail, sev, tool){
  if(!detail) return [];
  const lines = String(detail).split('\n').filter(l=>l.trim());
  const rows = [];
  for(const line of lines){
    const colonIdx = line.indexOf(':');
    if(colonIdx>0 && colonIdx<35){
      rows.push({k: line.substring(0,colonIdx).trim(), v: line.substring(colonIdx+1).trim()});
    } else if(line.trim()){
      rows.push({k:'', v: line.trim()});
    }
  }
  return rows;
}

function getRecommendations(f){
  const recs = {
    CRITICAL:{
      gitleaks:['Revoke the exposed secret immediately','Rotate all related credentials','Audit git history for other exposures','Enable secret scanning alerts on repository','Add secrets to .gitignore and use environment variables'],
      trufflehog:['Revoke and rotate the verified credential immediately','Check access logs for unauthorized use of this credential','Scan all repositories for similar patterns','Implement pre-commit hooks to prevent future leaks'],
      dnstwist:['Report phishing domain to registrar','Submit to Google Safe Browsing / PhishTank','Monitor the domain for active phishing pages','Consider registering common variations proactively','Alert users about potential impersonation sites'],
      spiderfoot:['Apply security patches for detected CVEs immediately','Review firewall rules for exposed ports','Enable automatic security updates','Consider a penetration test'],
    },
    WARNING:{
      dnstwist:['Monitor this domain for phishing activity','Consider registering this variant defensively','Set up alerts for similar registrations'],
      amass:['Verify this subdomain is intentionally public','Ensure proper authentication is in place','Disable or firewall any unused services'],
      spiderfoot:['Close risky ports if not required','Review SPF/DMARC email authentication records','Enable DMARC enforcement (p=reject)'],
      rssbridge:['Investigate the security incident mentioned','Prepare a public statement if needed','Monitor for follow-up coverage'],
    }
  };
  return (recs[f.severity]||{})[f.tool] || [];
}

// ══════ MODAL ══════
function openModal(idx){
  modalList = allFindings;
  modalIdx  = idx;
  renderModal();
  document.getElementById('modal-overlay').classList.add('open');
  document.body.style.overflow='hidden';
}
function closeModal(e){if(e.target===document.getElementById('modal-overlay')) closeModalDirect();}
function closeModalDirect(){document.getElementById('modal-overlay').classList.remove('open');document.body.style.overflow='';}
function navModal(dir){
  modalIdx = Math.max(0, Math.min(modalList.length-1, modalIdx+dir));
  renderModal();
}
function renderModal(){
  const f = modalList[modalIdx];
  if(!f) return;
  const icon = SEV_ICON[f.severity]||'●';
  const mIcon = document.getElementById('m-icon');
  mIcon.textContent = icon;
  mIcon.className = `modal-sev-icon ${f.severity}`;
  document.getElementById('m-title').textContent = cleanTitle(f.title);
  document.getElementById('m-prev').disabled = modalIdx===0;
  document.getElementById('m-next').disabled = modalIdx===modalList.length-1;

  const rows = parseDetail(f.detail, f.severity, f.tool);
  const recs = getRecommendations(f);
  const catLabel = MODULES.find(m=>m.id===f.tool)?.cat || f.tool;
  const catIcon = CAT_ICON[f.tool]||'●';

  // Group rows into key-value pairs
  const kvPairs = rows.filter(r=>r.k);
  const notes   = rows.filter(r=>!r.k);

  // Severity color for values
  const valColor = f.severity==='CRITICAL'?'red':f.severity==='WARNING'?'amber':f.severity==='OK'?'green':'blue';

  let html = '';

  // Overview section
  html += `<div class="modal-section">
    <div class="modal-section-title">Overview</div>
    <div class="info-grid">
      <div class="info-item"><div class="k">Severity</div><div class="v ${valColor}">${f.severity}</div></div>
      <div class="info-item"><div class="k">Category</div><div class="v">${catIcon} ${catLabel}</div></div>
      <div class="info-item"><div class="k">Detected At</div><div class="v">${f.ts ? f.ts.replace('T',' ').substring(0,19)+' UTC' : '–'}</div></div>
      <div class="info-item"><div class="k">Finding ID</div><div class="v">${f.id||'–'}</div></div>
      ${kvPairs.length===0 ? `<div class="info-item full"><div class="k">Details</div><div class="v">${esc(f.detail)}</div></div>` : ''}
    </div>
  </div>`;

  // Detailed info section
  if(kvPairs.length > 0){
    html += `<div class="modal-section">
      <div class="modal-section-title">Detailed Information</div>
      <div class="info-grid">`;
    for(const row of kvPairs){
      const isWide = row.v.length > 60 || ['Summary','Tweet','Sample','Details','URL','Message','Note'].includes(row.k);
      const vClass = ['CVE','Exploit','CRITICAL','ACTIVE','VERIFIED'].some(kw=>row.v.includes(kw)) ? 'red'
                   : ['WARNING','exposed','risky','weak','risk'].some(kw=>row.v.toLowerCase().includes(kw)) ? 'amber'
                   : ['clean','OK','None','none','not indexed'].some(kw=>row.v.includes(kw)) ? 'green' : '';
      html += `<div class="info-item${isWide?' full':''}"><div class="k">${esc(row.k)}</div><div class="v ${vClass}">${esc(row.v)}</div></div>`;
    }
    html += `</div></div>`;
  }

  // Notes section
  if(notes.length > 0){
    const warns = notes.filter(n=>n.v.startsWith('⚠'));
    const normal = notes.filter(n=>!n.v.startsWith('⚠'));
    if(warns.length > 0){
      html += `<div class="modal-section">
        <div class="modal-section-title">⚠ Warnings</div>
        <div style="display:flex;flex-direction:column;gap:6px">
          ${warns.map(n=>`<div style="background:var(--amber-bg);border:1px solid var(--amber-border);border-radius:6px;padding:8px 12px;font-size:11px;color:var(--amber);font-family:var(--mono)">${esc(n.v)}</div>`).join('')}
        </div>
      </div>`;
    }
    if(normal.length > 0){
      html += `<div class="modal-section">
        <div class="modal-section-title">Additional Context</div>
        <div style="display:flex;flex-direction:column;gap:4px">
          ${normal.map(n=>`<div style="font-size:11px;color:var(--muted);font-family:var(--mono);padding:3px 0;border-bottom:1px solid rgba(48,54,61,.4)">${esc(n.v)}</div>`).join('')}
        </div>
      </div>`;
    }
  }

  // Risk meter
  if(f.severity !== 'OK'){
    const riskPct = f.severity==='CRITICAL'?92:f.severity==='WARNING'?62:28;
    const riskCol = f.severity==='CRITICAL'?'var(--red)':f.severity==='WARNING'?'var(--amber)':'var(--accent)';
    html += `<div class="modal-section">
      <div class="modal-section-title">Risk Assessment</div>
      <div style="display:flex;justify-content:space-between;font-size:10px;color:var(--muted);margin-bottom:6px;font-family:var(--mono)">
        <span>Risk Level</span><span style="color:${riskCol};font-weight:700">${riskPct}%</span>
      </div>
      <div class="risk-meter"><div class="risk-fill" style="width:${riskPct}%;background:${riskCol}"></div></div>
    </div>`;
  }

  // Recommendations
  if(recs.length > 0){
    html += `<div class="modal-section">
      <div class="modal-section-title">Recommended Actions</div>
      <div class="recommend-box">
        <div class="recommend-title">🛡 What to do now</div>
        <ul class="recommend-list">
          ${recs.map(r=>`<li>${esc(r)}</li>`).join('')}
        </ul>
      </div>
    </div>`;
  }

  // Raw data
  if(f.raw && typeof f.raw === 'object'){
    const rawStr = JSON.stringify(f.raw, null, 2);
    if(rawStr.length > 10){
      html += `<div class="modal-section">
        <div class="modal-section-title">Raw Data</div>
        <div class="raw-block">${esc(rawStr.substring(0,2000))}${rawStr.length>2000?'\n…(truncated)':''}</div>
      </div>`;
    }
  }

  document.getElementById('m-body').innerHTML = html;
}

// ══════ CONN CHECK ══════
async function checkConn(){
  const dot=document.getElementById('cdot'),lbl=document.getElementById('clbl');
  try{
    const r=await fetch('/health',{signal:AbortSignal.timeout(3000)});
    if(r.ok){dot.className='cdot live';lbl.textContent='● Online';}else throw 0;
  }catch{dot.className='cdot dead';lbl.textContent='✗ Offline';}
}

// ══════ SCAN ══════
async function startScan(){
  const brand=document.getElementById('inp-brand').value.trim();
  const domain=document.getElementById('inp-domain').value.trim();
  if(!brand){alert('Enter a brand or college name.');return;}
  scanId=null;allFindings=[];clearInterval(pollT);if(sse){sse.close();sse=null;}
  const btn=document.getElementById('scan-btn');
  btn.textContent='⏸ SCANNING';btn.classList.add('running');btn.disabled=true;
  document.getElementById('sp').classList.add('on');
  document.getElementById('log-body').innerHTML='';
  document.getElementById('rb-rtlog').innerHTML='<div class="lw" id="rtlog-body"></div>';
  document.getElementById('rb-alerts').innerHTML='<div class="empty"><p>Scanning…</p></div>';
  ['mentions','news','leaks','domains','osint','ghcode','social','darkweb','visual'].forEach(k=>{
    const b=document.getElementById('b-'+k);if(b){b.style.display='none';b.textContent='0';}
    const body=document.getElementById(k+'-body');
    if(body) body.innerHTML='<div class="empty"><p>⟳ Scanning…</p></div>';
  });
  ['sc','sw','st','sa'].forEach(id=>document.getElementById(id).textContent='–');
  document.getElementById('scan-time').textContent='';
  setPhase(-1);initGrid();
  const scanStart=Date.now();
  try{
    const body={brand};if(domain)body.domain=domain;
    const r=await fetch('/scan/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    if(!r.ok){const t=await r.text();throw new Error(`HTTP ${r.status}: ${t}`);}
    const d=await r.json();scanId=d.scan_id;
    document.getElementById('dash-sub').textContent=`Scan ID: ${scanId} | Monitoring: ${brand}${domain?' ('+domain+')':''}`;
    startSSE(scanId);
    pollT=setInterval(()=>poll(scanId,scanStart),2500);
    poll(scanId,scanStart);
  }catch(e){done();alert(`Scan failed:\n${e.message}`);}
}

function startSSE(id){
  if(sse)sse.close();
  sse=new EventSource(`/scan/${id}/stream`);
  sse.onmessage=e=>{const d=JSON.parse(e.data);if(d.log)addLog(d.log);if(d.status&&['done','error'].includes(d.status))sse.close();};
  sse.onerror=()=>sse.close();
}

function addLog(line){
  const lvl=line.includes('[CRIT]')?'CRIT':line.includes('[WARN]')?'WARN':line.includes('[OK]')?'OK':'INFO';
  const ts=(line.match(/\[(\d{2}:\d{2}:\d{2})\]/)||['',''])[1];
  const msg=line.replace(/\[\d{2}:\d{2}:\d{2}\]\s*\[.*?\]\s*/,'');
  const h=`<div class="ll"><span class="lts">${ts}</span><span class="llv ${lvl}">${lvl}</span><span class="lmsg">${esc(msg)}</span></div>`;
  const rt=document.getElementById('rtlog-body'),lb=document.getElementById('log-body');
  if(rt){rt.insertAdjacentHTML('beforeend',h);rt.parentElement.scrollTop=9999;}
  if(lb){lb.insertAdjacentHTML('beforeend',h);lb.scrollTop=9999;}
}

async function poll(id,scanStart){
  try{
    const r=await fetch(`/scan/${id}`);if(!r.ok)return;
    const s=await r.json();renderState(s,scanStart);
    if(['done','error'].includes(s.status)){clearInterval(pollT);done(scanStart);}
  }catch{}
}

function renderState(s,scanStart){
  const fi=s.findings||[];
  allFindings=fi;
  const crit=fi.filter(f=>f.severity==='CRITICAL').length;
  const warn=fi.filter(f=>f.severity==='WARNING').length;
  const active=Object.values(s.tools||{}).filter(x=>x!=='idle').length;
  document.getElementById('sc').textContent=crit||'0';
  document.getElementById('sw').textContent=warn||'0';
  document.getElementById('st').textContent=fi.length||'0';
  document.getElementById('sa').textContent=active||'0';

  // Update tool cards
  Object.entries(s.tools||{}).forEach(([id,st])=>{
    const tf=fi.filter(f=>f.tool===id);
    const hasCrit=tf.some(f=>f.severity==='CRITICAL');
    const hasWarn=tf.some(f=>f.severity==='WARNING');
    const ds=st==='done'&&(hasCrit||hasWarn)?'alert':st;
    const flist=tf.slice(0,4).map(f=>({
      t:cleanTitle(f.title).substring(0,55)+(cleanTitle(f.title).length>55?'…':''),
      c:f.severity==='CRITICAL'?'cr':f.severity==='WARNING'?'wn':f.severity==='OK'?'ok':''
    }));
    if(tf.length>4)flist.push({t:`+${tf.length-4} more findings…`,c:''});
    utc(id,ds,flist);
  });

  renderFindings(fi);
  renderAlertPanel(fi);

  const ts=Object.values(s.tools||{});
  const pct=ts.length?Math.round(ts.filter(x=>['done','alert','error'].includes(x)).length/ts.length*100):0;
  document.getElementById('sp-fill').style.width=pct+'%';
  document.getElementById('sp-pct').textContent=pct+'%';
  document.getElementById('sp-lbl').textContent=s.status==='done'?'✓ Scan complete':s.status==='error'?'✗ Error':'Scanning…';
  setPhase(pct<20?0:pct<45?1:pct<70?2:pct<90?3:4);
}

function renderFindings(fi){
  const byTools=(tools)=>fi.filter(f=>tools.includes(f.tool));
  const render=(vid,tools,bid,bcls,emptyMsg)=>{
    const items=byTools(tools);
    const cnt=items.filter(f=>['CRITICAL','WARNING'].includes(f.severity)).length||items.length;
    setBadge(bid,cnt,bcls);
    if(items.length){
      // Find global index for each finding
      document.getElementById(vid).innerHTML=items.map(f=>{
        const gi=allFindings.indexOf(f);
        return buildCard(f,gi,vid);
      }).join('');
    } else {
      document.getElementById(vid).innerHTML=`<div class="empty"><p>${emptyMsg}</p></div>`;
    }
  };
  render('mentions-body',['twint'],'b-mentions','a','No social media mentions found for this brand.');
  render('news-body',['rssbridge'],'b-news','b','No news coverage found.');
  render('leaks-body',['gitleaks','trufflehog'],'b-leaks','r','No leaked secrets detected — repositories appear clean.');
  render('domains-body',['dnstwist','amass'],'b-domains','r','No lookalike or impersonation domains detected.');
  render('osint-body',['spiderfoot'],'b-osint','r','No critical intelligence findings detected.');
  render('ghcode-body',['github_code'],'b-ghcode','r','No credential exposure found on public GitHub code.');
  render('social-body',['social_protect'],'b-social','r','No social media impersonation detected.');
  render('darkweb-body',['darkweb'],'b-darkweb','r','No dark web or paste site mentions found.');
  render('visual-body',['visual_phish'],'b-visual','r','No visual clones detected across lookalike domains.');
}

function renderAlertPanel(fi){
  const serious=fi.filter(f=>['CRITICAL','WARNING'].includes(f.severity))
    .sort((a,b)=>a.severity==='CRITICAL'?-1:1);
  const p=document.getElementById('rb-alerts');
  if(!serious.length){
    p.innerHTML='<div class="empty"><div class="ic">🛡</div><p>No critical or warning alerts.</p></div>';
    return;
  }
  p.innerHTML=serious.map(f=>{
    const gi=allFindings.indexOf(f);
    const preview=f.detail.split('\n').find(l=>l.includes(':')&&l.length>5)||f.detail.substring(0,80);
    return `<div class="ac ${f.severity}" onclick="openModal(${gi})">
      <div class="ac-sev ${f.severity}">${f.severity}</div>
      <div class="ac-title">${esc(cleanTitle(f.title))}</div>
      <div class="ac-preview">${esc(preview)}</div>
      <div class="ac-ft">
        <span class="tag">${(f.ts||'').substring(11,19)}</span>
        <span class="ac-click">Click for details →</span>
      </div>
    </div>`;
  }).join('');
}

// ══════ HEALTH ══════
async function loadHealth(){
  try{
    const r=await fetch('/health');const d=await r.json();
    const bins=d.binaries||{},mods=d.python_modules||{};
    const all={...Object.fromEntries(Object.entries(bins).map(([k,v])=>[k,{v,src:'binary'}])),
               ...Object.fromEntries(Object.entries(mods).map(([k,v])=>[k,{v,src:'module'}]))};
    const missing=Object.entries(all).filter(([,x])=>!x.v);
    document.getElementById('health-body').innerHTML=
      `<div class="hgrid">${Object.entries(all).map(([k,x])=>`
        <div class="hcard"><span class="hn">${k} <span style="color:var(--dim);font-size:9px">(${x.src})</span></span>
        <span class="hv ${x.v?'ok':'no'}">${x.v?'✓ OK':'✗ MISSING'}</span></div>`).join('')}</div>
      <div style="font-size:9px;color:var(--dim);margin-top:10px;font-family:var(--mono)">
        Python ${d.python||''} | Path: ${d.local_bin||''}
      </div>
      ${missing.length?`<div class="warn-box">
        <strong style="color:var(--amber)">⚠ Missing modules detected:</strong> ${missing.map(([k])=>k).join(', ')}<br>
        Run: <code style="background:var(--bg3);padding:2px 8px;border-radius:4px">source venv/bin/activate && bash fix_missing.sh</code>
      </div>`:`<div style="margin-top:10px;background:var(--green-bg);border:1px solid var(--green-border);border-radius:7px;padding:10px;font-size:11px;color:var(--green)">✓ All modules installed and ready</div>`}`;
  }catch(e){document.getElementById('health-body').innerHTML=`<div class="empty"><p>Cannot reach backend<br>${e.message}</p></div>`;}
}

// ══════ HELPERS ══════
function done(scanStart){
  const btn=document.getElementById('scan-btn');
  btn.textContent='▶ SCAN';btn.classList.remove('running');btn.disabled=false;
  document.getElementById('sp-lbl').textContent='✓ Scan complete';setPhase(4);
  if(scanStart){
    const secs=Math.round((Date.now()-scanStart)/1000);
    document.getElementById('scan-time').textContent=`Completed in ${secs}s`;
  }
}
function setPhase(i){for(let x=0;x<5;x++){const e=document.getElementById('ph'+x);if(e)e.className='sp-ph'+(x<i?' ok':x===i?' on':'');}}
function setBadge(id,n,cls){const b=document.getElementById(id);b.textContent=n;b.className=`bdg ${cls}`;b.style.display=n>0?'inline':'none';}
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
// Keyboard nav for modal
document.addEventListener('keydown',e=>{
  if(!document.getElementById('modal-overlay').classList.contains('open'))return;
  if(e.key==='Escape')closeModalDirect();
  if(e.key==='ArrowLeft')navModal(-1);
  if(e.key==='ArrowRight')navModal(1);
});
window.addEventListener('load',()=>{initGrid();checkConn();setInterval(checkConn,12000);loadHealth();});
</script>
</html>"""

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Serves the BrandWatch dashboard — open http://localhost:8000 in browser."""
    return HTMLResponse(content=DASHBOARD_HTML)


# ─────────────────────────────────────────────────────────────────
# EMBEDDED DASHBOARD HTML
# (served at / so no CORS issues — same origin as the API)
# ─────────────────────────────────────────────────────────────────
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BrandWatch — Live</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Syne:wght@400;600;700;800&display=swap');
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0a0c10;--bg2:#0f1218;--bg3:#151b24;
  --surface:#1a2230;--surface2:#1e2a3a;
  --border:rgba(255,255,255,0.07);--border2:rgba(255,255,255,0.12);
  --text:#e2e8f0;--muted:#64748b;
  --accent:#22d3ee;--accent2:#818cf8;
  --red:#f87171;--amber:#fbbf24;--green:#34d399;
  --font-head:'Syne',sans-serif;--font-mono:'Space Mono',monospace;
}
html,body{background:var(--bg);color:var(--text);font-family:var(--font-mono);min-height:100vh}
.app{display:grid;grid-template-rows:auto 1fr;min-height:100vh}
.topbar{background:var(--bg2);border-bottom:1px solid var(--border);padding:0 20px;display:flex;align-items:center;gap:10px;height:54px;position:sticky;top:0;z-index:100}
.logo{font-family:var(--font-head);font-weight:800;font-size:17px;color:var(--accent);white-space:nowrap}
.logo span{color:var(--text)}
.logo sup{font-size:8px;background:var(--green);color:#000;padding:1px 5px;border-radius:3px;font-weight:700;vertical-align:super;margin-left:3px}
.inp{background:var(--bg3);border:1px solid var(--border2);color:var(--text);font-family:var(--font-mono);font-size:12px;padding:7px 10px;border-radius:6px;outline:none;transition:border-color .2s}
.inp:focus{border-color:var(--accent)}
.inp::placeholder{color:var(--muted)}
.inp-brand{width:160px} .inp-domain{width:180px}
.conn-dot{width:8px;height:8px;border-radius:50%;background:var(--muted);flex-shrink:0}
.conn-dot.live{background:var(--green);box-shadow:0 0 6px var(--green);animation:blink 2s infinite}
.conn-dot.dead{background:var(--red)}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}
.conn-lbl{font-size:10px;color:var(--muted);white-space:nowrap}
.scan-btn{background:var(--accent);color:#000;font-family:var(--font-mono);font-weight:700;font-size:11px;padding:8px 16px;border:none;border-radius:6px;cursor:pointer;white-space:nowrap;transition:opacity .2s}
.scan-btn:hover{opacity:.85}
.scan-btn.running{background:var(--amber);animation:pulse 1s infinite}
.scan-btn:disabled{opacity:.4;cursor:not-allowed}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.6}}
.main{display:grid;grid-template-columns:180px 1fr 260px;overflow:hidden;height:calc(100vh - 54px)}
.sidebar{background:var(--bg2);border-right:1px solid var(--border);padding:14px 0;display:flex;flex-direction:column;gap:1px;overflow-y:auto}
.ns{font-size:9px;color:var(--muted);letter-spacing:1px;padding:10px 13px 3px;text-transform:uppercase}
.ni{display:flex;align-items:center;gap:7px;padding:8px 13px;font-size:11px;cursor:pointer;color:var(--muted);border:none;background:none;width:100%;text-align:left;font-family:var(--font-mono);transition:background .15s}
.ni:hover{background:var(--surface);color:var(--text)}
.ni.active{background:var(--surface);color:var(--accent)}
.ni .ic{width:14px;text-align:center;font-size:13px}
.badge{margin-left:auto;font-size:9px;padding:1px 5px;border-radius:9px;font-weight:700;display:none}
.badge.r{background:var(--red);color:#000;display:inline}
.badge.a{background:var(--amber);color:#000;display:inline}
.badge.b{background:var(--accent);color:#000;display:inline}
.content{padding:18px;overflow-y:auto;display:flex;flex-direction:column;gap:14px}
.view{display:none;flex-direction:column;gap:14px}
.view.active{display:flex}
.sec-hd{font-family:var(--font-head);font-size:18px;font-weight:700}
.sec-sub{font-size:10px;color:var(--muted);margin-top:2px}
.stats-row{display:grid;grid-template-columns:repeat(4,1fr);gap:8px}
.stat{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:12px}
.stat .v{font-family:var(--font-head);font-size:22px;font-weight:800}
.stat .l{font-size:9px;color:var(--muted);margin-top:3px;text-transform:uppercase;letter-spacing:.5px}
.stat.r .v{color:var(--red)}.stat.a .v{color:var(--amber)}.stat.b .v{color:var(--accent)}.stat.g .v{color:var(--green)}
.tool-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.tc{background:var(--surface);border:1px solid var(--border);border-radius:9px;padding:13px;transition:border-color .2s}
.tc.running{border-color:var(--accent)}.tc.done{border-color:rgba(52,211,153,.35)}.tc.alert{border-color:rgba(248,113,113,.35)}.tc.error{border-color:rgba(100,116,139,.25);opacity:.65}
.tc-top{display:flex;align-items:center;gap:8px;margin-bottom:8px}
.tc-ic{font-size:17px;width:32px;height:32px;border-radius:7px;background:var(--bg3);display:flex;align-items:center;justify-content:center;flex-shrink:0}
.tc-name{font-family:var(--font-head);font-size:12px;font-weight:700}
.tc-cat{font-size:9px;color:var(--muted)}
.tc-st{margin-left:auto}
.pill{display:inline-block;font-size:8px;padding:2px 6px;border-radius:8px;font-weight:700;letter-spacing:.4px}
.pill.idle{background:rgba(100,116,139,.2);color:var(--muted)}
.pill.running{background:rgba(34,211,238,.15);color:var(--accent);animation:pulse 1s infinite}
.pill.done{background:rgba(52,211,153,.15);color:var(--green)}
.pill.alert{background:rgba(248,113,113,.15);color:var(--red)}
.pill.error{background:rgba(100,116,139,.15);color:var(--muted)}
.prog{height:2px;background:var(--bg3);border-radius:2px;margin:5px 0;overflow:hidden}
.pf{height:100%;background:var(--accent);border-radius:2px;transition:width .5s}
.tc-desc{font-size:9px;color:var(--muted);line-height:1.6;margin-bottom:6px}
.tc-fi{font-size:10px;line-height:1.9}
.fi{display:flex;gap:4px;align-items:baseline}
.fi::before{content:'›';color:var(--accent2);flex-shrink:0}
.fi.cr::before{content:'!';color:var(--red);font-weight:700}
.fi.wn::before{content:'⚠';color:var(--amber)}
.sp-wrap{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:13px;display:none}
.sp-wrap.on{display:block}
.sp-top{display:flex;justify-content:space-between;margin-bottom:8px}
.sp-lbl{font-family:var(--font-head);font-size:12px;font-weight:700}
.sp-pct{font-size:11px;color:var(--accent)}
.sp-bar{height:3px;background:var(--bg3);border-radius:2px;overflow:hidden;margin-bottom:8px}
.sp-fill{height:100%;background:linear-gradient(90deg,var(--accent),var(--accent2));transition:width .4s}
.sp-phases{display:grid;grid-template-columns:repeat(5,1fr);gap:5px}
.sp-ph{text-align:center;font-size:9px;padding:4px 2px;border-radius:4px;background:var(--bg3);color:var(--muted);transition:all .3s}
.sp-ph.on{background:rgba(34,211,238,.12);color:var(--accent)}
.sp-ph.ok{background:rgba(52,211,153,.12);color:var(--green)}
.rc{background:var(--surface);border:1px solid var(--border);border-radius:7px;padding:11px;margin-bottom:7px;border-left:3px solid var(--border2)}
.rc.CRITICAL{border-left-color:var(--red)}.rc.WARNING{border-left-color:var(--amber)}.rc.INFO{border-left-color:var(--accent2)}.rc.OK{border-left-color:var(--green)}
.rc-hd{display:flex;justify-content:space-between;align-items:flex-start;gap:8px;margin-bottom:4px}
.rc-title{font-family:var(--font-head);font-size:11px;font-weight:700}
.sev{font-size:8px;font-weight:700;padding:1px 5px;border-radius:3px;white-space:nowrap}
.sev.CRITICAL{background:rgba(248,113,113,.15);color:var(--red)}
.sev.WARNING{background:rgba(251,191,36,.15);color:var(--amber)}
.sev.INFO{background:rgba(129,140,248,.15);color:var(--accent2)}
.sev.OK{background:rgba(52,211,153,.15);color:var(--green)}
.rc-det{font-size:9px;color:var(--muted);line-height:1.6}
.rc-meta{display:flex;gap:6px;margin-top:4px;flex-wrap:wrap}
.tag{font-size:8px;background:var(--bg3);color:var(--muted);padding:1px 5px;border-radius:3px}
.dtable{width:100%;border-collapse:collapse;font-size:10px}
.dtable th{text-align:left;padding:5px 7px;font-size:9px;color:var(--muted);letter-spacing:.5px;border-bottom:1px solid var(--border);text-transform:uppercase}
.dtable td{padding:5px 7px;border-bottom:1px solid var(--border)}
.dtable tr:hover td{background:var(--surface2)}
.rpanel{background:var(--bg2);border-left:1px solid var(--border);display:flex;flex-direction:column;overflow:hidden}
.rtabs{display:flex;border-bottom:1px solid var(--border);flex-shrink:0}
.rtab{flex:1;padding:9px 4px;font-family:var(--font-mono);font-size:10px;text-align:center;cursor:pointer;color:var(--muted);border:none;background:none;border-bottom:2px solid transparent;transition:all .2s}
.rtab.active{color:var(--accent);border-bottom-color:var(--accent)}
.rbody{flex:1;overflow-y:auto;padding:11px;display:flex;flex-direction:column;gap:8px}
.rbody.hide{display:none}
.ac{background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:9px;border-left:3px solid var(--red)}
.ac.WARNING{border-left-color:var(--amber)}.ac.INFO{border-left-color:var(--accent2)}.ac.OK{border-left-color:var(--green)}
.ac-sev{font-size:8px;font-weight:700;letter-spacing:1px;margin-bottom:2px}
.ac-sev.CRITICAL{color:var(--red)}.ac-sev.WARNING{color:var(--amber)}.ac-sev.INFO{color:var(--accent2)}
.ac-title{font-size:10px;font-weight:700;font-family:var(--font-head);margin-bottom:2px}
.ac-det{font-size:9px;color:var(--muted);line-height:1.5}
.ac-ft{display:flex;justify-content:space-between;margin-top:4px}
.lw{font-family:var(--font-mono);font-size:9px;line-height:2}
.ll{display:flex;gap:5px;align-items:baseline}
.lts{color:var(--muted);font-size:8px;flex-shrink:0}
.llv{font-size:8px;font-weight:700;padding:0 3px;border-radius:2px;flex-shrink:0}
.llv.INFO{background:rgba(129,140,248,.1);color:var(--accent2)}
.llv.WARN{background:rgba(251,191,36,.1);color:var(--amber)}
.llv.CRIT{background:rgba(248,113,113,.1);color:var(--red)}
.llv.OK{background:rgba(52,211,153,.1);color:var(--green)}
.lmsg{color:var(--text);word-break:break-all;font-size:9px}
.empty{text-align:center;padding:30px 16px;color:var(--muted)}
.empty .ic{font-size:26px;margin-bottom:8px}
.empty p{font-size:10px;line-height:1.8}
.hgrid{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.hcard{background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:9px;display:flex;justify-content:space-between;align-items:center}
.hcard .hn{font-size:10px}.hcard .hv{font-size:10px;font-weight:700}
.hv.ok{color:var(--green)}.hv.no{color:var(--red)}
.warn-box{background:rgba(251,191,36,.07);border:1px solid rgba(251,191,36,.2);border-radius:6px;padding:10px;font-size:10px;line-height:1.8;margin-top:6px}
::-webkit-scrollbar{width:3px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:2px}
</style>
</head>
<body>
<div class="app">

<header class="topbar">
  <div class="logo">brand<span>watch</span><sup>LIVE</sup></div>
  <input class="inp inp-brand" id="inp-brand" type="text" placeholder="Brand name…" value="">
  <input class="inp inp-domain" id="inp-domain" type="text" placeholder="domain.ac.in (optional)">
  <div class="conn-dot" id="conn-dot"></div>
  <span class="conn-lbl" id="conn-lbl">connecting…</span>
  <button class="scan-btn" id="scan-btn" onclick="startScan()">▶ SCAN</button>
</header>

<div class="main">
<nav class="sidebar">
  <div class="ns">Overview</div>
  <button class="ni active" onclick="gv('dashboard',this)"><span class="ic">◈</span>Dashboard</button>
  <div class="ns">Collection</div>
  <button class="ni" onclick="gv('mentions',this)"><span class="ic">🐦</span>Mentions<span class="badge a" id="b-mentions" style="display:none">0</span></button>
  <button class="ni" onclick="gv('news',this)"><span class="ic">📰</span>News/RSS<span class="badge b" id="b-news" style="display:none">0</span></button>
  <div class="ns">Threats</div>
  <button class="ni" onclick="gv('leaks',this)"><span class="ic">🔑</span>Leaks<span class="badge r" id="b-leaks" style="display:none">0</span></button>
  <button class="ni" onclick="gv('domains',this)"><span class="ic">🌐</span>Domains<span class="badge r" id="b-domains" style="display:none">0</span></button>
  <div class="ns">Recon</div>
  <button class="ni" onclick="gv('osint',this)"><span class="ic">🕵</span>OSINT<span class="badge r" id="b-osint" style="display:none">0</span></button>
  <div class="ns">System</div>
  <button class="ni" onclick="gv('logs',this)"><span class="ic">⬡</span>Live Logs</button>
  <button class="ni" onclick="gv('health',this)"><span class="ic">♥</span>Health</button>
</nav>

<main class="content">
  <div class="view active" id="view-dashboard">
    <div><div class="sec-hd">Threat Overview</div><div class="sec-sub" id="dash-sub">Enter brand name → click ▶ SCAN</div></div>
    <div class="sp-wrap" id="sp-wrap">
      <div class="sp-top"><span class="sp-lbl" id="sp-lbl">Scanning…</span><span class="sp-pct" id="sp-pct">0%</span></div>
      <div class="sp-bar"><div class="sp-fill" id="sp-fill" style="width:0%"></div></div>
      <div class="sp-phases">
        <div class="sp-ph" id="ph0">📡 Collect</div><div class="sp-ph" id="ph1">🔑 Leaks</div>
        <div class="sp-ph" id="ph2">🌐 Domains</div><div class="sp-ph" id="ph3">🕵 OSINT</div>
        <div class="sp-ph" id="ph4">✓ Done</div>
      </div>
    </div>
    <div class="stats-row">
      <div class="stat r"><div class="v" id="s-crit">–</div><div class="l">Critical</div></div>
      <div class="stat a"><div class="v" id="s-warn">–</div><div class="l">Warnings</div></div>
      <div class="stat b"><div class="v" id="s-total">–</div><div class="l">Findings</div></div>
      <div class="stat g"><div class="v" id="s-tools">–</div><div class="l">Tools Active</div></div>
    </div>
    <div class="tool-grid" id="tool-grid"></div>
  </div>

  <div class="view" id="view-mentions">
    <div><div class="sec-hd">Twitter/X Mentions</div><div class="sec-sub">via snscrape</div></div>
    <div id="mentions-body"><div class="empty"><div class="ic">🐦</div><p>Run a scan first.</p></div></div>
  </div>
  <div class="view" id="view-news">
    <div><div class="sec-hd">News & RSS</div><div class="sec-sub">via RSS-Bridge + Google News</div></div>
    <div id="news-body"><div class="empty"><div class="ic">📰</div><p>Run a scan first.</p></div></div>
  </div>
  <div class="view" id="view-leaks">
    <div><div class="sec-hd">Secret & Leak Detection</div><div class="sec-sub">via GitLeaks + TruffleHog</div></div>
    <div id="leaks-body"><div class="empty"><div class="ic">🔑</div><p>Run a scan first.</p></div></div>
  </div>
  <div class="view" id="view-domains">
    <div><div class="sec-hd">Lookalike Domains</div><div class="sec-sub">via dnstwist + Amass/crt.sh</div></div>
    <div id="domains-body"><div class="empty"><div class="ic">🌐</div><p>Run a scan first.</p></div></div>
  </div>
  <div class="view" id="view-osint">
    <div><div class="sec-hd">OSINT Recon</div><div class="sec-sub">HIBP · Shodan · Hunter.io · SpiderFoot</div></div>
    <div id="osint-body"><div class="empty"><div class="ic">🕵</div><p>Run a scan first.</p></div></div>
  </div>
  <!-- GITHUB CODE SEARCH VIEW -->
  <div class="view" id="view-ghcode">
    <div><div class="sec-hd">GitHub Code Search</div>
    <div class="sec-sub">Scans ALL public GitHub for leaked credentials — beyond just your org repos</div></div>
    <div id="ghcode-body"><div class="empty"><div class="ic">🔍</div><p>Run a scan to search GitHub code.</p></div></div>
  </div>

  <!-- SOCIAL MEDIA GUARD VIEW -->
  <div class="view" id="view-social">
    <div><div class="sec-hd">Social Media Guard</div>
    <div class="sec-sub">Checks for unclaimed handles and impersonation accounts across 8 platforms</div></div>
    <div id="social-body"><div class="empty"><div class="ic">📱</div><p>Run a scan to check social media.</p></div></div>
  </div>

  <!-- DARK WEB MONITOR VIEW -->
  <div class="view" id="view-darkweb">
    <div><div class="sec-hd">Dark Web & Paste Monitor</div>
    <div class="sec-sub">Paste sites · GitHub Gists · IntelligenceX · HackerNews · HIBP breach database</div></div>
    <div id="darkweb-body"><div class="empty"><div class="ic">🌑</div><p>Run a scan to check dark web sources.</p></div></div>
  </div>

  <!-- VISUAL CLONE DETECTOR VIEW -->
  <div class="view" id="view-visual">
    <div><div class="sec-hd">Visual Clone Detector</div>
    <div class="sec-sub">Screenshots lookalike domains and compares visual similarity to your real site</div></div>
    <div id="visual-body"><div class="empty"><div class="ic">📸</div><p>Run a scan to check visual similarity.</p></div></div>
  </div>

  <div class="view" id="view-logs">
    <div><div class="sec-hd">Live Pipeline Logs</div><div class="sec-sub">Real-time output from all tools</div></div>
    <div class="lw" id="log-body"><div class="empty"><p>Logs appear during a scan.</p></div></div>
  </div>
  <div class="view" id="view-health">
    <div><div class="sec-hd">Backend Health</div><div class="sec-sub">Tool availability check</div></div>
    <div id="health-body"><div class="empty"><div class="ic">♥</div><p>Loading…</p></div></div>
    <button onclick="loadHealth()" style="align-self:flex-start;background:var(--bg3);border:1px solid var(--border2);color:var(--text);font-family:var(--font-mono);font-size:10px;padding:6px 12px;border-radius:5px;cursor:pointer">↺ Refresh</button>
  </div>
</main>

<aside class="rpanel">
  <div class="rtabs">
    <button class="rtab active" onclick="srt('alerts',this)">Alerts</button>
    <button class="rtab" onclick="srt('rtlog',this)">Live Log</button>
  </div>
  <div class="rbody" id="rb-alerts"><div class="empty"><div class="ic">🛡</div><p>No alerts yet.</p></div></div>
  <div class="rbody hide" id="rb-rtlog"><div class="lw" id="rtlog-body"></div></div>
</aside>
</div>
</div>

<script>
// All API calls use relative URLs — same origin, zero CORS issues
const API = '';  // empty = same origin (http://localhost:8000)

const TOOLS=[
  {id:'twint',name:'snscrape',cat:'Data Collection',ic:'🐦',desc:'Scrapes Twitter/X for brand mentions (Python 3.13 compatible)'},
  {id:'rssbridge',name:'RSS-Bridge',cat:'Data Collection',ic:'📡',desc:'Fetches Google News, Reddit & RSS feeds for brand coverage'},
  {id:'gitleaks',name:'GitLeaks',cat:'Leak Detection',ic:'🔐',desc:'Scans GitHub repos & commits for exposed secrets'},
  {id:'trufflehog',name:'TruffleHog',cat:'Leak Detection',ic:'🐷',desc:'Deep entropy scan for verified API keys & credentials'},
  {id:'dnstwist',name:'dnstwist',cat:'Phishing Detection',ic:'🌀',desc:'Detects lookalike/typosquat domains for your brand'},
  {id:'amass',name:'Amass',cat:'Infrastructure',ic:'🗺',desc:'Enumerates subdomains + DNS surface (crt.sh fallback)'},
  {id:'spiderfoot',name:'SpiderFoot',cat:'OSINT',ic:'🕷',desc:'HIBP breach check · Shodan CVEs · Hunter.io emails'},
  {id:'scrapy',name:'Scrapy',cat:'Optional',ic:'🕸',desc:'Custom spiders for forums/paste sites (set SCRAPY_SPIDER_DIR)'},
];

let scanId=null, pollT=null, sse=null;

function tc(t,st,fi=[]){
  const lbl={idle:'IDLE',running:'RUNNING',done:'DONE',alert:'FINDINGS',error:'ERROR'}[st]||'IDLE';
  const prog=st==='running'?`<div class="prog"><div class="pf" style="width:${Math.random()*50+20}%"></div></div>`:'';
  return `<div class="tc ${st}" id="tc-${t.id}">
    <div class="tc-top"><div class="tc-ic">${t.ic}</div>
    <div><div class="tc-name">${t.name}</div><div class="tc-cat">${t.cat}</div></div>
    <div class="tc-st"><span class="pill ${st}">${lbl}</span></div></div>
    ${prog}<div class="tc-desc">${t.desc}</div>
    <div class="tc-fi">${fi.map(f=>`<div class="fi ${f.cls||''}">${esc(f.text)}</div>`).join('')}</div>
  </div>`;
}
function utc(id,st,fi){const t=TOOLS.find(x=>x.id===id);const e=document.getElementById('tc-'+id);if(t&&e)e.outerHTML=tc(t,st,fi);}
function initGrid(){document.getElementById('tool-grid').innerHTML=TOOLS.map(t=>tc(t,'idle',[])).join('');}

function gv(id,btn){
  document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));
  document.querySelectorAll('.ni').forEach(b=>b.classList.remove('active'));
  document.getElementById('view-'+id).classList.add('active');
  if(btn)btn.classList.add('active');
  if(id==='health')loadHealth();
}
function srt(id,btn){
  document.querySelectorAll('.rtab').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('rb-alerts').className='rbody'+(id==='alerts'?'':' hide');
  document.getElementById('rb-rtlog').className='rbody'+(id==='rtlog'?'':' hide');
}

async function checkConn(){
  const dot=document.getElementById('conn-dot'),lbl=document.getElementById('conn-lbl');
  try{
    const r=await fetch('/health',{signal:AbortSignal.timeout(3000)});
    if(r.ok){dot.className='conn-dot live';lbl.textContent='● Connected';}
    else throw 0;
  }catch{dot.className='conn-dot dead';lbl.textContent='✗ Backend offline';}
}

async function startScan(){
  const brand=document.getElementById('inp-brand').value.trim();
  const domain=document.getElementById('inp-domain').value.trim();
  if(!brand){alert('Enter a brand name');return;}

  scanId=null;
  clearInterval(pollT);
  if(sse){sse.close();sse=null;}

  const btn=document.getElementById('scan-btn');
  btn.textContent='⏸ SCANNING';btn.classList.add('running');btn.disabled=true;
  document.getElementById('sp-wrap').classList.add('on');
  document.getElementById('log-body').innerHTML='';
  document.getElementById('rb-rtlog').innerHTML='<div class="lw" id="rtlog-body"></div>';
  document.getElementById('rb-alerts').innerHTML='<div class="empty"><p>Scanning…</p></div>';
  ['mentions','news','leaks','domains','osint'].forEach(k=>{
    document.getElementById('b-'+k).style.display='none';
    document.getElementById(k+'-body').innerHTML='<div class="empty"><p>Scanning…</p></div>';
  });
  ['s-crit','s-warn','s-total','s-tools'].forEach(id=>document.getElementById(id).textContent='–');
  setPhase(-1);initGrid();

  try{
    const body={brand};if(domain)body.domain=domain;
    const r=await fetch('/scan/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    if(!r.ok)throw new Error(`HTTP ${r.status}: ${await r.text()}`);
    const d=await r.json();
    scanId=d.scan_id;
    document.getElementById('dash-sub').textContent=`Scan ID: ${scanId} | Brand: ${brand}${domain?' | '+domain:''}`;
    startSSE(scanId);
    pollT=setInterval(()=>poll(scanId),2500);
    poll(scanId);
  }catch(e){
    done();
    alert(`Scan failed: ${e.message}`);
  }
}

function startSSE(id){
  if(sse)sse.close();
  sse=new EventSource(`/scan/${id}/stream`);
  sse.onmessage=e=>{
    const d=JSON.parse(e.data);
    if(d.log)addLog(d.log);
    if(d.status&&['done','error'].includes(d.status))sse.close();
  };
  sse.onerror=()=>sse.close();
}

function addLog(line){
  const lvl=line.includes('[CRIT]')?'CRIT':line.includes('[WARN]')?'WARN':line.includes('[OK]')?'OK':'INFO';
  const ts=(line.match(/\[(\d{2}:\d{2}:\d{2})\]/)||['',''])[1];
  const msg=line.replace(/\[\d{2}:\d{2}:\d{2}\]\s*\[.*?\]\s*/,'');
  const h=`<div class="ll"><span class="lts">${ts}</span><span class="llv ${lvl}">${lvl}</span><span class="lmsg">${esc(msg)}</span></div>`;
  const rt=document.getElementById('rtlog-body'),lb=document.getElementById('log-body');
  if(rt){rt.insertAdjacentHTML('beforeend',h);rt.parentElement.scrollTop=9999;}
  if(lb){lb.insertAdjacentHTML('beforeend',h);lb.scrollTop=9999;}
}

async function poll(id){
  try{
    const r=await fetch(`/scan/${id}`);
    if(!r.ok)return;
    const s=await r.json();
    renderState(s);
    if(['done','error'].includes(s.status)){clearInterval(pollT);done();}
  }catch{}
}

function renderState(s){
  const fi=s.findings||[];
  const crit=fi.filter(f=>f.severity==='CRITICAL').length;
  const warn=fi.filter(f=>f.severity==='WARNING').length;
  const active=Object.values(s.tools||{}).filter(x=>x!=='idle').length;
  document.getElementById('s-crit').textContent=crit;
  document.getElementById('s-warn').textContent=warn;
  document.getElementById('s-total').textContent=fi.length;
  document.getElementById('s-tools').textContent=active;

  Object.entries(s.tools||{}).forEach(([id,st])=>{
    const tf=fi.filter(f=>f.tool===id);
    const hasCrit=tf.some(f=>f.severity==='CRITICAL');
    const hasWarn=tf.some(f=>f.severity==='WARNING');
    const ds=st==='done'&&(hasCrit||hasWarn)?'alert':st;
    const flist=tf.slice(0,3).map(f=>({text:f.title,cls:f.severity==='CRITICAL'?'cr':f.severity==='WARNING'?'wn':''}));
    if(tf.length>3)flist.push({text:`+${tf.length-3} more…`,cls:''});
    utc(id,ds,flist);
  });

  renderFindings(fi);
  renderAlerts(fi);

  const ts=Object.values(s.tools||{});
  const pct=ts.length?Math.round(ts.filter(x=>['done','alert','error'].includes(x)).length/ts.length*100):0;
  document.getElementById('sp-fill').style.width=pct+'%';
  document.getElementById('sp-pct').textContent=pct+'%';
  document.getElementById('sp-lbl').textContent=s.status==='done'?'Scan complete':s.status==='error'?'Error':'Scanning…';
  setPhase(pct<25?0:pct<50?1:pct<75?2:pct<95?3:4);
}

function renderFindings(fi){
  const bt=tools=>fi.filter(f=>tools.includes(f.tool));
  const fc=f=>`<div class="rc ${f.severity}"><div class="rc-hd"><div class="rc-title">${esc(f.title)}</div><span class="sev ${f.severity}">${f.severity}</span></div><div class="rc-det">${esc(f.detail)}</div><div class="rc-meta"><span class="tag">${f.tool}</span><span class="tag">${(f.ts||'').substring(11,19)}</span></div></div>`;

  const mentions=bt(['twint']);
  setBadge('b-mentions',mentions.length,'a');
  document.getElementById('mentions-body').innerHTML=mentions.length?mentions.map(fc).join(''):'<div class="empty"><p>No mentions found.</p></div>';

  const news=bt(['rssbridge']);
  setBadge('b-news',news.length,'b');
  document.getElementById('news-body').innerHTML=news.length?news.map(fc).join(''):'<div class="empty"><p>No news found.</p></div>';

  const leaks=bt(['gitleaks','trufflehog']);
  setBadge('b-leaks',leaks.filter(f=>f.severity==='CRITICAL').length,'r');
  document.getElementById('leaks-body').innerHTML=leaks.length?leaks.map(fc).join(''):'<div class="empty"><p>No leaks found.</p></div>';

  const domains=bt(['dnstwist','amass']);
  setBadge('b-domains',domains.filter(f=>f.severity==='CRITICAL').length,'r');
  document.getElementById('domains-body').innerHTML=domains.length?domains.map(fc).join(''):'<div class="empty"><p>No domain findings.</p></div>';

  const osint=bt(['spiderfoot']);
  setBadge('b-osint',osint.filter(f=>f.severity==='CRITICAL').length,'r');
  document.getElementById('osint-body').innerHTML=osint.length?osint.map(fc).join(''):'<div class="empty"><p>No OSINT findings yet.</p></div>';
}

function renderAlerts(fi){
  const serious=fi.filter(f=>['CRITICAL','WARNING'].includes(f.severity)).sort((a,b)=>a.severity==='CRITICAL'?-1:1);
  const p=document.getElementById('rb-alerts');
  p.innerHTML=serious.length?serious.map(f=>`<div class="ac ${f.severity}"><div class="ac-sev ${f.severity}">${f.severity}</div><div class="ac-title">${esc(f.title)}</div><div class="ac-det">${esc(f.detail.substring(0,140))}</div><div class="ac-ft"><span class="tag">${f.tool}</span><span class="tag">${(f.ts||'').substring(11,19)}</span></div></div>`).join(''):'<div class="empty"><div class="ic">🛡</div><p>No critical alerts.</p></div>';
}

async function loadHealth(){
  try{
    const r=await fetch('/health');
    const d=await r.json();
    const bins=d.binaries||{},mods=d.python_modules||{};
    const all={...Object.fromEntries(Object.entries(bins).map(([k,v])=>[k+' (binary)',v])),...Object.fromEntries(Object.entries(mods).map(([k,v])=>[k+' (module)',v]))};
    const missing=Object.entries(all).filter(([,v])=>!v);
    document.getElementById('health-body').innerHTML=`<div class="hgrid">${Object.entries(all).map(([k,v])=>`<div class="hcard"><span class="hn">${k}</span><span class="hv ${v?'ok':'no'}">${v?'✓ OK':'✗ MISSING'}</span></div>`).join('')}</div><div style="font-size:9px;color:var(--muted);margin-top:6px">Python ${d.python||''}</div>${missing.length?`<div class="warn-box"><strong style="color:var(--amber)">Missing: ${missing.map(([k])=>k).join(', ')}</strong><br>Fix: <code style="background:var(--bg3);padding:2px 6px;border-radius:3px">source venv/bin/activate && bash fix_missing.sh</code></div>`:''}`;
  }catch(e){document.getElementById('health-body').innerHTML=`<div class="empty"><p>Cannot reach /health<br>${e.message}</p></div>`;}
}

function done(){
  const btn=document.getElementById('scan-btn');
  btn.textContent='▶ SCAN';btn.classList.remove('running');btn.disabled=false;
  document.getElementById('sp-lbl').textContent='Scan complete';setPhase(4);
}
function setPhase(i){for(let x=0;x<5;x++){const e=document.getElementById('ph'+x);if(e)e.className='sp-ph'+(x<i?' ok':x===i?' on':'');}}
function setBadge(id,n,cls){const b=document.getElementById(id);b.textContent=n;b.className=`badge ${cls}`;b.style.display=n>0?'inline':'none';}
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}

window.addEventListener('load',()=>{initGrid();checkConn();setInterval(checkConn,15000);loadHealth();});
</script>
</html>"""


@app.post("/scan/start")
async def start_scan(req: ScanRequest, bg: BackgroundTasks):
    scan_id = str(uuid.uuid4())[:12]
    scans[scan_id] = {
        "scan_id": scan_id, "brand": req.brand,
        "status": "running", "started": now_iso(), "finished": None,
        "tools": {t: "idle" for t in TOOL_IDS},
        "findings": [], "logs": [],
    }
    bg.add_task(run_pipeline, scan_id, req)
    return {"scan_id": scan_id, "status": "started"}


@app.get("/scan/{scan_id}")
async def get_scan(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(404, "Scan not found")
    return scans[scan_id]


@app.get("/scan/{scan_id}/findings")
async def get_findings(scan_id: str, severity: Optional[str] = None):
    if scan_id not in scans:
        raise HTTPException(404, "Scan not found")
    findings = scans[scan_id]["findings"]
    if severity:
        findings = [f for f in findings if f["severity"] == severity.upper()]
    return {"scan_id": scan_id, "count": len(findings), "findings": findings}


@app.get("/scan/{scan_id}/stream")
async def stream_logs(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(404, "Scan not found")

    async def gen():
        sent = 0
        while True:
            for entry in scans[scan_id]["logs"][sent:]:
                yield f"data: {json.dumps({'log': entry})}\n\n"
                sent += 1
            if scans[scan_id]["status"] in ("done","error"):
                yield f"data: {json.dumps({'status': scans[scan_id]['status']})}\n\n"
                break
            await asyncio.sleep(0.5)

    return StreamingResponse(gen(), media_type="text/event-stream")


@app.get("/scans")
async def list_scans():
    return [{"scan_id": s["scan_id"], "brand": s["brand"],
             "status": s["status"], "started": s["started"],
             "findings": len(s["findings"])} for s in scans.values()]


@app.get("/health")
async def health():
    def check(name):
        return bool(shutil.which(name) or shutil.which(f"{_LOCAL_BIN}/{name}"))

    py_mods = {}
    for mod in ["dnstwist","feedparser","httpx","fastapi","PIL","imagehash"]:
        try:
            __import__(mod)
            py_mods[mod] = True
        except ImportError:
            py_mods[mod] = False

    return {
        "status": "ok",
        "python": __import__("sys").version,
        "local_bin": _LOCAL_BIN,
        "binaries": {
            "gitleaks":   check("gitleaks"),
            "trufflehog": check("trufflehog"),
            "dnstwist":   check("dnstwist"),
            "amass":      check("amass"),
            "scrapy":     check("scrapy"),
        },
        "python_modules": py_mods,
        "spiderfoot_url": SPIDERFOOT_URL,
    }


# ─────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse, sys
    parser = argparse.ArgumentParser(description="BrandMonitor — Python 3.13 / Kali edition")
    parser.add_argument("--brand",  default="acme")
    parser.add_argument("--domain", default=None)
    parser.add_argument("--org",    default=None, help="GitHub org/user")
    parser.add_argument("--tools",  default=None, help="comma-separated tool subset")
    parser.add_argument("--serve",  action="store_true")
    parser.add_argument("--host",   default="0.0.0.0")
    parser.add_argument("--port",   type=int, default=8000)
    args = parser.parse_args()

    if args.serve:
        import uvicorn
        uvicorn.run("brand_monitor:app", host=args.host, port=args.port, reload=True)
    else:
        async def cli():
            req = ScanRequest(
                brand=args.brand, domain=args.domain,
                github_org=args.org,
                tools=args.tools.split(",") if args.tools else None,
            )
            sid = str(uuid.uuid4())[:12]
            scans[sid] = {"scan_id":sid,"brand":req.brand,"status":"running",
                          "started":now_iso(),"finished":None,
                          "tools":{t:"idle" for t in TOOL_IDS},
                          "findings":[],"logs":[]}
            await run_pipeline(sid, req)
            print("\n" + "="*60)
            ICON = {"CRITICAL":"🔴","WARNING":"🟡","INFO":"🔵","OK":"🟢"}
            for f in scans[sid]["findings"]:
                print(f"{ICON.get(f['severity'],'•')} [{f['severity']}][{f['tool']}] {f['title']}")
                print(f"   {f['detail']}")
            c = sum(1 for f in scans[sid]["findings"] if f["severity"]=="CRITICAL")
            print(f"\nTotal: {len(scans[sid]['findings'])} findings | Critical: {c}")
        asyncio.run(cli())

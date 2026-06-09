#!/usr/bin/env python3
"""pip install requests apscheduler"""
import os, urllib3, requests
from datetime import datetime
from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

def ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

print(f"[{ts()}] Starting Nessus scheduler...")

BASE = f"{os.environ.get('NESSUS_HOST', '<INPUT_URL>')}:8834"
print(f"[{ts()}] Target: {BASE}")
HEADERS = {"X-ApiKeys": f"accessKey={os.environ['NESSUS_ACCESS_KEY']}; "
                        f"secretKey={os.environ['NESSUS_SECRET_KEY']}"}
print(f"[{ts()}] API keys loaded from environment.")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#  { scan_id: (start_cron, stop_cron) }
SCHEDULES = {
    1012: ({"day_of_week": "mon-sun", "hour": 17, "minute": 0},
         {"day_of_week": "mon-sun", "hour": 7, "minute": 0}),
}

def act(scan_id, action):
    print(f"[{ts()}] FIRING: {action} on scan {scan_id}...")
    try:
        r = requests.post(f"{BASE}/scans/{scan_id}/{action}", headers=HEADERS, verify=False, timeout=30)
        r.raise_for_status()
        print(f"[{ts()}] SUCCESS: {action} -> scan {scan_id} [{r.status_code}]")
    except requests.exceptions.RequestException as e:
        print(f"[{ts()}] ERROR: {action} -> scan {scan_id} FAILED: {e}")

# Per-scan desired state: True = should be running, False = should be paused.
# None until first set, so the first decision for a scan always fires.
_running = {}

def set_running(scan_id, running):
    """Idempotent wrapper around act(): only hit the API when the scan's desired
    state actually changes. This lets the secondary timing check (reconcile) run
    every minute without spamming resume/pause when nothing has changed."""
    if _running.get(scan_id) is running:
        return
    _running[scan_id] = running
    act(scan_id, "resume" if running else "pause")

def in_window(now, start, stop):
    """True if `now` falls inside the [start, stop) daily window. start/stop are
    the cron dicts from SCHEDULES; handles windows that wrap past midnight
    (e.g. 17:00-07:00 = inside from 17:00 to 06:59)."""
    cur = now.hour * 60 + now.minute
    s = start["hour"] * 60 + start["minute"]
    e = stop["hour"] * 60 + stop["minute"]
    if s <= e:
        return s <= cur < e
    return cur >= s or cur < e

def reconcile():
    """Secondary timing check: a level-triggered safety net that runs every
    minute and drives each scan to the state the wall clock says it should be in.
    Because set_running is idempotent this is silent except right at a window
    boundary or after a cron edge was missed (e.g. the host was asleep at 17:00
    and only woke later) — in which case it self-corrects within ~1 minute."""
    now = datetime.now()
    for sid, (start, stop) in SCHEDULES.items():
        set_running(sid, in_window(now, start, stop))

sched = BlockingScheduler()  # add timezone="America/New_York" if jobs fire at the wrong time
print(f"[{ts()}] Scheduler timezone: {sched.timezone}")

for sid, (start, stop) in SCHEDULES.items():
    sched.add_job(set_running, CronTrigger(**start), args=[sid, True])
    sched.add_job(set_running, CronTrigger(**stop),  args=[sid, False])
    print(f"[{ts()}] Registered scan {sid}: start={start}, stop={stop}")

# Secondary timing check: re-check every minute so a missed cron edge (host
# asleep at the boundary, clock skew, restart mid-window) self-corrects within
# ~1 minute instead of waiting for the next edge.
sched.add_job(reconcile, IntervalTrigger(minutes=1), id="reconcile")
print(f"[{ts()}] Registered secondary timing check (every 1 min).")

print(f"[{ts()}] Upcoming jobs:")
for j in sched.get_jobs():
    print(f"[{ts()}]   {j.args}")

# Drive each scan to the correct state right now, before blocking on start(), so
# a scheduler launched mid-window acts immediately rather than waiting for an edge.
print(f"[{ts()}] Reconciling initial scan state...")
reconcile()

print(f"[{ts()}] Scheduler running. Waiting for scheduled times... (Ctrl+C to stop)")
try:
    sched.start()
except (KeyboardInterrupt, SystemExit):
    print(f"[{ts()}] Scheduler stopped.")
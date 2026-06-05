#!/usr/bin/env python3
"""Minimal Nessus scan scheduler (no cron). pip install requests apscheduler"""
import os, urllib3, requests
from datetime import datetime
from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.cron import CronTrigger

def ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

print(f"[{ts()}] Starting Nessus scheduler...")

BASE = f"{os.environ.get('NESSUS_HOST', 'https://localhost')}:8834"
print(f"[{ts()}] Target: {BASE}")
HEADERS = {"X-ApiKeys": f"accessKey={os.environ['NESSUS_ACCESS_KEY']}; "
                        f"secretKey={os.environ['NESSUS_SECRET_KEY']}"}
print(f"[{ts()}] API keys loaded from environment.")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# scan_id: (start_cron, stop_cron) -- cron fields as dicts
SCHEDULES = {
    12: ({"day_of_week": "mon-sun", "hour": 17, "minute": 0},
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

sched = BlockingScheduler()  # add timezone="America/New_York" if jobs fire at the wrong time
print(f"[{ts()}] Scheduler timezone: {sched.timezone}")

for sid, (start, stop) in SCHEDULES.items():
    sched.add_job(act, CronTrigger(**start), args=[sid, "resume"])
    sched.add_job(act, CronTrigger(**stop),  args=[sid, "pause"])
    print(f"[{ts()}] Registered scan {sid}: start={start}, stop={stop}")

print(f"[{ts()}] Upcoming jobs:")
for j in sched.get_jobs():
    nrt = getattr(j, "next_run_time", "n/a (APScheduler 4.x — pin to <4 for this info)")
    print(f"[{ts()}]   {j.args} -> next run {nrt}")

print(f"[{ts()}] Scheduler running. Waiting for scheduled times... (Ctrl+C to stop)")
try:
    sched.start()
except (KeyboardInterrupt, SystemExit):
    print(f"[{ts()}] Scheduler stopped.")
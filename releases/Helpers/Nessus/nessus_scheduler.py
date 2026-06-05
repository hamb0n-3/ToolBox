#!/usr/bin/env python3
"""pip install requests apscheduler"""
import os, urllib3, requests
from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.cron import CronTrigger

BASE = f"{os.environ.get('NESSUS_HOST', '')}:8834"
HEADERS = {"X-ApiKeys": f"accessKey={os.environ['NESSUS_ACCESS_KEY']}; "
                        f"secretKey={os.environ['NESSUS_SECRET_KEY']}"}
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#  { scan_id: (start_cron, stop_cron) }
SCHEDULES = {
    3783: ({"day_of_week": "mon-sun", "hour": 17, "minute": 0}, {"day_of_week": "mon-sun", "hour": 7, "minute": 0}),
}

def act(scan_id, action):
    requests.post(f"{BASE}/scans/{scan_id}/{action}", headers=HEADERS, verify=False)
    print(f"{action} -> scan {scan_id}")

sched = BlockingScheduler()
for sid, (start, stop) in SCHEDULES.items():
    sched.add_job(act, CronTrigger(**start), args=[sid, "launch"])
    sched.add_job(act, CronTrigger(**stop),  args=[sid, "stop"])
sched.start()
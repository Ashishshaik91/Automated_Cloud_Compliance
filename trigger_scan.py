import urllib.request, urllib.error
import json

data = json.dumps({"organization_id": 1}).encode('utf-8')
req = urllib.request.Request('http://localhost:8000/api/v1/scans/trigger', data=data, method='POST')
req.add_header('Content-Type', 'application/json')
# The endpoint requires auth. Let's see if we can trigger the task directly via celery!
from app.tasks import run_scheduled_scan
import asyncio

asyncio.run(run_scheduled_scan())

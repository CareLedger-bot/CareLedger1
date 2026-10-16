"""Render screenshots from the app's actual HTTP responses.

Requires Playwright and a Chromium browser for documentation only.
No third-party packages are required to RUN the CareLedger application.
"""
from __future__ import annotations

import http.cookiejar
import re
import tempfile
import threading
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import build_opener, HTTPCookieProcessor, Request

import app
from playwright.sync_api import sync_playwright


def main():
    folder = Path(__file__).parent / 'screenshots'
    folder.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        dbfile = Path(td) / 'demo.sqlite3'
        app.init_db(dbfile)
        server = app.CareLedgerServer(('127.0.0.1',0),dbfile)
        thread = threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        base = f'http://127.0.0.1:{server.server_port}'
        opener = build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))

        def get(path):
            return opener.open(base+path).read().decode('utf-8')

        def post(path, values):
            data=urlencode(values).encode('utf-8')
            request=Request(base+path,data=data,method='POST',headers={'Content-Type':'application/x-www-form-urlencoded'})
            return opener.open(request).read().decode('utf-8')

        try:
            with sync_playwright() as pw:
                browser=pw.chromium.launch(headless=True,executable_path='/usr/bin/chromium',args=['--no-sandbox'])
                page=browser.new_page(viewport={'width':1440,'height':900},device_scale_factor=1)

                def capture(html,name):
                    page.set_content(html,wait_until='load')
                    page.screenshot(path=str(folder/name),full_page=True)
                    print('Rendered',name)

                capture(get('/login'),'01-sign-in.png')
                capture(post('/login',{'username':'clinician','password':app.DEMO_PASSWORD}),'02-patient-overview.png')
                new_html=get('/patients/new')
                capture(new_html,'03-create-patient.png')
                csrf=re.search(r'name="csrf" value="([^"]+)"',new_html).group(1)
                new_page=post('/patients', {'csrf':csrf,'full_name':'Jordan Taylor','date_of_birth':'1999-04-12','appointment_date':'2026-11-25','care_summary':'Fictional appointment review for portfolio demonstration.','status':'Active'})
                pid=6
                capture(new_page,'04-created-patient.png')
                edited=post(f'/patients/{pid}/update', {'csrf':csrf,'full_name':'Jordan Taylor','date_of_birth':'1999-04-12','appointment_date':'2026-11-25','care_summary':'Fictional appointment review updated after demonstration.','status':'Follow-up'})
                capture(edited,'05-record-and-change-history.png')
                capture(get('/audit'),'06-audit-trail.png')
                browser.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


if __name__=='__main__':
    main()

import argparse
import hashlib
import os
import sys
import json
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description='Observe the static blocked receipt-status front with no external requests.')
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
OUT = args.output
OUT.mkdir(exist_ok=True)
source = (ROOT/'space/governed-receipt-verifier/index.html').read_bytes()
report = {'source_sha256': hashlib.sha256(source).hexdigest(), 'scope': 'Isolated candidate informational page; all provider requests blocked; no receipt verification or live publication claim', 'source_revision': os.environ.get('SOURCE_REVISION', 'LOCAL_UNCOMMITTED'), 'complete': False, 'cases': [], 'failures': []}
variants = [(w,1,False,True) for w in [320,390,768,1280,1920]] + [(w,z,False,True) for w in [390,1280] for z in [2,4]] + [(390,1,True,True),(390,1,False,False)]
(OUT/'report.json').write_text(json.dumps(report,indent=2)+'\n')
with sync_playwright() as p:
    browser = None
    try:
        browser=p.chromium.launch(headless=True)
        for width,scale,forced,js in variants:
            errors=[]; writes=[]; external=[]
            context=browser.new_context(viewport={'width':width,'height':900},java_script_enabled=js,reduced_motion='reduce',forced_colors='active' if forced else 'none')
            def route(r):
                if r.request.method != 'GET': writes.append(r.request.method+' '+r.request.url)
                if r.request.url=='https://status.local/': r.fulfill(status=200,body=source,content_type='text/html')
                else: external.append(r.request.url); r.abort()
            context.route('**/*',route)
            page=context.new_page(); page.on('pageerror',lambda e:errors.append(str(e)))
            page.goto('https://status.local/',wait_until='load')
            if scale!=1: page.add_style_tag(content=f'html{{font-size:{scale*100}%}}')
            checks={}
            checks['no_horizontal_document_overflow']=page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1')
            checks['descendant_text_contained']=page.evaluate('''() => [...document.querySelectorAll('h1,h2,p,li,nav a,.button')].every(e=>{const r=e.getBoundingClientRect();return r.left>=-1&&r.right<=innerWidth+1})''')
            checks['one_heading']=page.locator('h1').count()==1
            checks['blocked_visible']=page.get_by_text('BLOCKED · NO VERIFICATION PERFORMED',exact=True).is_visible()
            checks['no_verification_controls']=page.locator('form,input,textarea,button,script,iframe').count()==0
            checks['mark_dimensions']=page.locator('.identity svg').evaluate('(e)=>{const r=e.getBoundingClientRect();return r.width===40&&r.height===40}')
            targets=[]
            for link in page.locator('a:not(.skip-link)').all():
                link.scroll_into_view_if_needed()
                targets.append(link.evaluate('''e=>{const r=e.getBoundingClientRect();const x=(Math.max(0,r.left)+Math.min(innerWidth,r.right))/2,y=(Math.max(0,r.top)+Math.min(innerHeight,r.bottom))/2;const hit=document.elementFromPoint(x,y);return {text:e.innerText,width:r.width,height:r.height,hit:hit===e||e.contains(hit)}}'''))
            checks['targets_44_and_hit']=all(t['width']>=44 and t['height']>=44 and t['hit'] for t in targets)
            page.evaluate('scrollTo(0,0)')
            page.locator('.skip-link').focus()
            checks['focus_visible']=page.locator('.skip-link').evaluate('(e)=>getComputedStyle(e).outlineWidth===\'3px\'')
            page.locator('.skip-link').press('Enter')
            checks['skip_moves_focus_to_main']=page.evaluate('document.activeElement.id===\'main\'')
            if forced:
                checks['forced_colors_solid_boundary']=page.locator('.foil').evaluate('(e)=>getComputedStyle(e).borderTopStyle===\'solid\'&&getComputedStyle(e).backgroundImage===\'none\'')
            checks['no_page_errors']=not errors
            checks['no_external_or_write_requests']=not writes and not external
            name=f'{width}-scale{scale}-forced{forced}-js{js}'
            overflow=page.evaluate('''() => [...document.querySelectorAll('body *')].filter(e=>{const r=e.getBoundingClientRect();return r.width&& (r.left < -1 || r.right > innerWidth+1)}).map(e=>({tag:e.tagName,classes:e.className?.baseVal??e.className,text:e.innerText?.slice(0,80)}))''')
            row={'name':name,'checks':checks,'targets':targets,'overflow_diagnostics':overflow,'errors':errors,'writes':writes,'external':external}
            report['cases'].append(row)
            report['failures'] += [name+':'+k for k,v in checks.items() if not v]
            if scale==1 and not forced and width in (320,1280) and js:
                page.evaluate('document.activeElement.blur();scrollTo(0,0)')
                page.screenshot(path=str(OUT/(name+'.png')),full_page=True)
            context.close()
        report['complete']=True
    except Exception as error:
        report['complete'] = False
        report['failures'].append(type(error).__name__+': '+str(error))
        print(type(error).__name__+': browser qualification did not complete', file=sys.stderr)
    finally:
        if browser is not None:
            browser.close()
        report['checks']=sum(len(c['checks']) for c in report['cases'])
        (OUT/'report.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'complete':report['complete'],'cases':len(report['cases']),'checks':report['checks'],'failures':report['failures']}))
raise SystemExit(bool(report['failures']) or not report['complete'])

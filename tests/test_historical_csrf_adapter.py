"""Exercise historical fetch adapter against real Request/Headers in Node.

The adapter is evaluated in isolation; no browser, server, network or cookies.
"""
from pathlib import Path
import subprocess
import unittest

ROOT=Path(__file__).resolve().parents[1]
JS=ROOT/"web/live-auth-overlay.js"
START="  const nativeFetch=window.fetch.bind(window);"
END="  const label={owner:"

class HistoricalCSRFAdapterTests(unittest.TestCase):
    def test_legacy_mutations_receive_modern_csrf_and_cross_origin_is_untouched(self):
        source=JS.read_text(encoding="utf8")
        self.assertEqual(source.count(START),1)
        self.assertEqual(source.count(END),1)
        snippet=START+source.split(START,1)[1].split(END,1)[0]
        harness=r"""
const assert=require('node:assert/strict');
const state={account:{id:1,role:'admin'},csrf:'trusted-modern',active:false};
const location={origin:'https://panel.example.net',href:'https://panel.example.net/'};
const recorded=[];
const window={fetch:(input,options)=>{
  recorded.push({input,options});
  return Promise.resolve({ok:true});
}};
"""+snippet+r"""
async function test(){
  await window.fetch('/api/nat/add',{
    method:'POST',headers:{'X-Cerato-CSRF':'obsolete','Content-Type':'application/json'},
    body:'{}'
  });
  let v=recorded.pop();
  assert.equal(v.options.headers.get('X-Cerato-CSRF'),'trusted-modern');
  assert.equal(v.options.headers.get('Content-Type'),'application/json');
  assert.equal(v.options.credentials,'same-origin');
  assert.equal(v.options.redirect,'error');
  await window.fetch(new Request('https://panel.example.net/api/ip/configure',{
    method:'POST',headers:{'X-Cerato-CSRF':'legacy-from-request'}
  }));
  v=recorded.pop();
  assert.equal(v.options.headers.get('X-Cerato-CSRF'),'trusted-modern');
  await window.fetch('https://outsider.example.org/api/nat/add',{
    method:'POST',headers:{'X-Cerato-CSRF':'legacy'}
  });
  v=recorded.pop();
  assert.equal(v.options.headers['X-Cerato-CSRF'],'legacy');
  assert.equal(v.options.credentials,undefined);
  await window.fetch('/api/auth/login',{method:'POST'});
  v=recorded.pop();
  assert.equal(v.options.headers,undefined);
  await window.fetch('/api/accounts/1',{method:'PATCH'});
  v=recorded.pop();
  assert.equal(v.options.headers,undefined);
  await window.fetch('/api/status',{method:'GET'});
  v=recorded.pop();
  assert.equal(v.options.headers,undefined);
  const old=recorded.length;
  state.account=null;
  await assert.rejects(window.fetch('/api/nat/add',{method:'POST'}));
  assert.equal(recorded.length,old);
  state.account={id:1};
  state.csrf='';
  await assert.rejects(window.fetch('/api/updates/install',{method:'POST'}));
  assert.equal(recorded.length,old);
  state.csrf='trusted-modern';
  state.active=true;
  await assert.rejects(window.fetch('/api/nat/remove',{method:'POST'}));
  assert.equal(recorded.length,old);
}
test().catch(e=>{console.error(e);process.exit(1)});
"""
        output=subprocess.run(["node","-e",harness],cwd=ROOT,timeout=12,
                              capture_output=True,text=True)
        self.assertEqual(output.returncode,0,output.stdout+"\n"+output.stderr)

    def test_native_auth_requests_do_not_loop_back_into_legacy_adapter(self):
        src=JS.read_text(encoding="utf8")
        self.assertIn("const response=await nativeFetch(path",src)
        self.assertIn("window.fetch=legacyFetch;",src)
        self.assertIn("headers['X-Cerato-CSRF']=state.csrf",src)
        for banned in ("sessionStorage","localStorage","document.cookie","eval(",
                       "innerHTML","credentials:'include'"):
            self.assertNotIn(banned,src)

if __name__=="__main__":
    unittest.main()

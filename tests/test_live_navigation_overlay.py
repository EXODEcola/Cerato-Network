"""Exercise historical screen hash restoration without executing deployed Web JS."""
from __future__ import annotations
import subprocess
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"integrations"))
from live_navigation_overlay import apply,NavigationStageError,MARKER,CODE

SOURCE="""let live={};let screen='overview';
const screens=['overview','ips','machines','nat','firewall','topology','logs','settings','updates'];
function render(){if(!live)return;
  globalThis.rendered=screen;
}
"""

class NavigationTests(unittest.TestCase):
    def test_navigation_hash_restores_on_page_reload_and_syncs_after_navigation(self):
        app=apply(SOURCE)
        self.assertIn(MARKER,app)
        self.assertEqual(app.count("ceratoNavigationSync();"),1)
        self.assertEqual(app.count("function render(){if(!live)return;"),1)
        self.assertNotIn("localStorage",app)
        self.assertNotIn("sessionStorage",app)
        self.assertNotIn("innerHTML",app)
        with tempfile.TemporaryDirectory() as t:
            file=Path(t)/"page.js"
            file.write_text(app)
            subprocess.run(["node","--check",str(file)],check=True,
                           capture_output=True,timeout=10)
            harness="""const fs=require('fs'),vm=require('vm'),assert=require('assert');
const app=fs.readFileSync(process.argv[1],'utf8');
const hash={value:'#/nat'};const events={};const histories=[];
const window={location:hash,history:{
replaceState(_state,_unused,path){hash.value=path;histories.push(path);}
},addEventListener(name,fn){events[name]=fn;}};
Object.defineProperty(hash,'hash',{get(){return this.value},set(x){this.value=x}});
const sandbox={window,console};
vm.runInNewContext(app+'; render();globalThis.initial=screen;screen="machines";render();globalThis.current=screen;',sandbox);
assert.equal(sandbox.initial,'nat');
assert.equal(sandbox.current,'machines');
assert.deepEqual(histories,['#/machines']);
hash.hash='#/updates';events.hashchange();
assert.equal(sandbox.rendered,'updates');
hash.hash='#/not-a-screen';events.hashchange();
assert.equal(sandbox.rendered,'updates');
console.log('PASS: F5, hashchange, scoped whitelist and route synchronization');
"""
            p=subprocess.run(["node","-e",harness,str(file)],
                 capture_output=True,text=True,timeout=10)
            self.assertEqual(p.returncode,0,p.stderr)

    def test_unknown_screen_or_second_patch_fails_closed(self):
        with self.assertRaises(NavigationStageError):
            apply("function render(){if(!live)return;}")
        with self.assertRaises(NavigationStageError):
            apply(apply(SOURCE))
        with self.assertRaises(NavigationStageError):
            apply(SOURCE.replace("function render(){if(!live)return;",
                 "function render(){if(!live)return;\nfunction render(){if(!live)return;"))

if __name__=="__main__":
    unittest.main()

"""Run the real wrapper against a fake pct; no Proxmox or guest writes."""
import os,subprocess,tempfile,unittest
from pathlib import Path
SOURCE=Path(__file__).parents[1]/'scripts/proxmox-guest-wrapper.sh'
class TransferCleanupTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'));self.root=Path(self.tmp.name);self.old=self.root/'ram';self.disk=self.root/'disk';self.old.mkdir();self.disk.mkdir(mode=0o700)
  fake=self.root/'pct';fake.write_text('''#!/usr/bin/env python3
import os,sys,time
from pathlib import Path
if os.environ.get('BLOCK'):
 Path(os.environ['READY']).touch();time.sleep(20)
if sys.argv[1]=='exec':sys.exit(18 if os.environ.get('MISSING') else 0)
if os.environ.get('FAIL'):sys.exit(17)
if os.environ.get('MISSING') and sys.argv[1] in ('pull','push'):
 print('failed to open source',file=sys.stderr);sys.exit(0)
if sys.argv[1]=='pull':Path(sys.argv[-1]).write_bytes(b'example\\x00audio')
else:Path(os.environ['CAPTURE']).write_bytes(Path(sys.argv[3]).read_bytes())
''');fake.chmod(0o700)
  text=SOURCE.read_text().replace('/usr/sbin/pct',str(fake)).replace('/var/lib/proxmox-guest-wrapper',str(self.disk)).replace('mktemp /tmp/proxmox-guest-wrapper.','mktemp '+str(self.old)+'/proxmox-guest-wrapper.').replace('  logger -t "$LOG_TAG" -- "$*"','  :').replace('0:700',str(os.getuid())+':700')
  self.wrapper=self.root/'wrapper';self.wrapper.write_text(text)
  self.env=dict(os.environ,CAPTURE=str(self.root/'capture'),READY=str(self.root/'ready'))
 def tearDown(self):self.tmp.cleanup()
 def run_wrapper(self,action,fail=False):
  env=dict(self.env,SSH_ORIGINAL_COMMAND=action+' 123 /guest/path with spaces.wav')
  if fail:env['FAIL']='1'
  return subprocess.run(['bash',str(self.wrapper)],input=b'payload',capture_output=True,env=env)
 def assert_clean(self):
  self.assertEqual(list(self.old.iterdir()),[],'RAM staging leaked');self.assertEqual(list(self.disk.rglob('*.??????')),[])
 def test_missing_pull_is_not_reported_as_success(self):
  self.env['MISSING']='1';result=self.run_wrapper('lxc-pull');self.assertNotEqual(result.returncode,0,result.stderr);self.assert_clean()
 def test_push_diagnostic_with_zero_exit_is_failure(self):
  self.env['MISSING']='1';result=self.run_wrapper('lxc-push');self.assertNotEqual(result.returncode,0,result.stderr);self.assert_clean()
 def test_pull_success_cleans_temporary(self):
  result=self.run_wrapper('lxc-pull');self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stdout,b'example\x00audio');self.assert_clean()
 def test_push_success_cleans_temporary(self):
  result=self.run_wrapper('lxc-push');self.assertEqual(result.returncode,0,result.stderr);self.assertEqual((self.root/'capture').read_bytes(),b'payload');self.assert_clean()
 def test_pull_failure_preserves_exit_and_cleans(self):
  result=self.run_wrapper('lxc-pull',True);self.assertEqual(result.returncode,17,result.stderr);self.assert_clean()
 def test_push_failure_preserves_exit_and_cleans(self):
  result=self.run_wrapper('lxc-push',True);self.assertEqual(result.returncode,17,result.stderr);self.assert_clean()
if __name__=='__main__':unittest.main(verbosity=2)

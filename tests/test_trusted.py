"""Offline-only automated checks. Real Windows/iOS signing needs device testing."""
from __future__ import annotations
import os
import plistlib
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock
from ipa_studio import core, privacy

ROOT = Path(__file__).resolve().parents[1]

class TrustedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.ipa = self.base / 'demo.ipa'
        with zipfile.ZipFile(self.ipa,'w') as z:
            z.writestr('Payload/App.app/Info.plist', plistlib.dumps({
                'CFBundleIdentifier':'com.sample.demo','CFBundleDisplayName':'Demo',
                'MinimumOSVersion':'16.0', 'CFBundleVersion':'1'}))

    def test_real_ipa_analysis(self):
        i = core.inspect_ipa(self.ipa)
        self.assertEqual(i.bundle_id,'com.sample.demo')
        self.assertEqual(i.name,'Demo')

    def test_reject_bad_ipa(self):
        x=self.base/'bad.ipa'; x.write_text('hi')
        with self.assertRaises(core.StudioError): core.inspect_ipa(x)

    def test_reject_multiple_payloads(self):
        x=self.base/'two.ipa'
        with zipfile.ZipFile(x,'w') as z:
            for a in ('App','Other'):
                z.writestr(f'Payload/{a}.app/Info.plist',plistlib.dumps({'CFBundleIdentifier':'com.test.app'}))
        with self.assertRaises(core.StudioError): core.inspect_ipa(x)

    def test_anisette_servers_exact_https(self):
        self.assertEqual(len(privacy.SERVERS),2)
        for u in privacy.SERVERS.values():
            self.assertEqual(privacy.server_host(u),u.split('/')[2])
        for u in ('http://new.ani.sidestore.io','https://evil.com','https://new.ani.sidestore.io.evil.com'):
            with self.assertRaises(ValueError): privacy.server_host(u)

    def test_reject_server_label_injection(self):
        with self.assertRaises(ValueError): privacy.selected_url('Other server')

    def test_apple_and_selected_only(self):
        server=privacy.SERVERS['SideStore V3']
        self.assertTrue(privacy.allowed_host('gsa.apple.com',server))
        self.assertTrue(privacy.allowed_host('new.ani.sidestore.io',server))
        self.assertFalse(privacy.allowed_host('mac-ani.jkcoxson.com',server))
        self.assertFalse(privacy.allowed_host('github.com',server))

    def test_policy_env_clears_proxy_and_insecure_overrides(self):
        with mock.patch.dict(os.environ, {'HTTPS_PROXY':'https://evil.org', 'IPASIDE_ANISETTE':'local',
                                         'IPASIDE_ANISETTE_SERVER':'https://evil.org','IPASIDE_CONNECTION':'wifi'}):
            e=core.secured_environment(privacy.SERVERS['SideStore V3'],password='very_secret',code='123456',email='a@icloud.com')
        self.assertNotIn('HTTPS_PROXY',e)
        self.assertEqual(e['IPASIDE_ANISETTE'],'remote')
        self.assertEqual(e['IPASIDE_CONNECTION'],'usb')
        self.assertEqual(e['IPASIDE_ANISETTE_SERVER'],privacy.SERVERS['SideStore V3'])
        self.assertEqual(e['IPASTUDIO_2FA_CODE'],'123456')
        self.assertEqual(e['IPASTUDIO_APPLE_EMAIL'],'a@icloud.com')
        self.assertEqual(e['IPASIDE_APPLE_PASSWORD'],'very_secret')
        self.assertTrue((Path(e['PYTHONPATH'])/'sitecustomize.py').is_file())

    def test_policy_denies_external_dns_before_network(self):
        script='import runpy; runpy.run_path(r"' + str(ROOT/'policy'/'sitecustomize.py') + '"); import socket; socket.getaddrinfo("github.com",443)'
        e=os.environ.copy()
        e['PYTHONPATH']=str(ROOT/'policy')
        e['IPASTUDIO_APPROVED_ANISETTE']=privacy.SERVERS['SideStore V3']
        result=subprocess.run([sys.executable,'-c',script],env=e,capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('PermissionError',result.stderr)
        self.assertIn('blocked DNS',result.stderr)

    def test_policy_blocks_direct_public_ip(self):
        script='import runpy; runpy.run_path(r"' + str(ROOT/'policy'/'sitecustomize.py') + '"); import socket; socket.socket().connect(("1.1.1.1",443))'
        e=os.environ.copy()
        e['PYTHONPATH']=str(ROOT/'policy')
        e['IPASTUDIO_APPROVED_ANISETTE']=privacy.SERVERS['SideStore V3']
        result=subprocess.run([sys.executable,'-c',script],env=e,capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('blocked outbound',result.stderr)

    def test_policy_allows_loopback_resolution(self):
        script='import runpy; runpy.run_path(r"' + str(ROOT/'policy'/'sitecustomize.py') + '"); import socket; print(socket.getaddrinfo("localhost",80)[0][0])'
        e=os.environ.copy();e['PYTHONPATH']=str(ROOT/'policy')
        result=subprocess.run([sys.executable,'-c',script],env=e,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_no_password_or_otp_in_process_args(self):
        exe=self.base/'python.exe';exe.write_bytes(b'fake')
        seen={}
        def fake_popen(args,env=None,logger=None):
            seen.update({'args':args,'env':env,'logger':logger})
            return (0,'{"status":"ok"}','')
        with mock.patch('ipa_studio.core.bundled_engine',return_value=exe),mock.patch('ipa_studio.core._popen',side_effect=fake_popen):
            r=core.run_engine(str(exe),['login'],server=privacy.SERVERS['SideStore V3'],password='secretXX',code='123456',email='a@icloud.com')
        self.assertEqual(r['status'],'ok')
        self.assertNotIn('secretXX',repr(seen['args']))
        self.assertNotIn('123456',repr(seen['args']))
        self.assertNotIn('a@icloud.com',repr(seen['args']))
        self.assertIsNone(seen['logger'])
        self.assertEqual(seen['env']['IPASTUDIO_2FA_CODE'],'123456')
        self.assertEqual(seen['env']['IPASTUDIO_APPLE_EMAIL'],'a@icloud.com')

    def test_engine_external_refused(self):
        exe=self.base/'fake.exe';exe.write_bytes(b'fake')
        with mock.patch('ipa_studio.core.bundled_engine',return_value=self.base/'trusted.exe'):
            with self.assertRaisesRegex(core.StudioError,'bundled'):
                core.run_engine(str(exe),['version'],server=privacy.SERVERS['SideStore V3'])

    def test_usb_only(self):
        exe=self.base/'python.exe';exe.write_bytes(b'fake')
        with mock.patch('ipa_studio.core.bundled_engine',return_value=exe):
            for tr in ('wifi','auto'):
                with self.assertRaisesRegex(core.StudioError,'USB'):
                    core.run_engine(str(exe),['devices','--connection',tr],server=privacy.SERVERS['SideStore V3'])

    def test_no_command_line_2fa(self):
        exe=self.base/'python.exe';exe.write_bytes(b'fake')
        with mock.patch('ipa_studio.core.bundled_engine',return_value=exe):
            with self.assertRaisesRegex(core.StudioError,'command line'):
                core.run_engine(str(exe),['login','--code','123456'],server=privacy.SERVERS['SideStore V3'])

    def test_errors_redact_password_and_otp(self):
        exe=self.base/'python.exe';exe.write_bytes(b'fake')
        with mock.patch('ipa_studio.core.bundled_engine',return_value=exe),mock.patch('ipa_studio.core._popen',return_value=(1,'{"status":"error","error":"secretXX or 123456"}','')):
            with self.assertRaises(core.StudioError) as ctx:
                core.run_engine(str(exe),['login'],server=privacy.SERVERS['SideStore V3'],password='secretXX',code='123456',email='a@icloud.com')
        self.assertNotIn('secretXX',str(ctx.exception))
        self.assertNotIn('123456',str(ctx.exception))

    def test_bundled_engine_resolved(self):
        exe=self.base/'app'/'IPAStudio.exe';exe.parent.mkdir();exe.write_bytes(b'x')
        engine=exe.parent/'engine'/'python'/'python.exe';engine.parent.mkdir(parents=True);engine.write_bytes(b'fake')
        with mock.patch.object(core.sys,'frozen',True,create=True),mock.patch.object(core.sys,'executable',str(exe)):
            self.assertEqual(core.bundled_engine(),engine)

    def test_gui_has_consent_and_workflow(self):
        from ipa_studio.ui import App
        for m in ('apple_login','sideload','engine_sign_only','refresh_all','scan_devices','_require_consent'):
            self.assertTrue(callable(getattr(App,m)))

if __name__ == '__main__': unittest.main()

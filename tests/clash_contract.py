#!/usr/bin/env python3
"""校验 Clash 全量规则、执行顺序、DNS 路径和厂商归属。需要 PyYAML。"""
import argparse
import json
from pathlib import Path
import sys
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
import engine
sys.path.insert(0, str(ROOT / "tools"))
from rule_syntax import parse_ruleset_call, render_call
from routing_manifest import load_routing_manifest


def rules(path):
    return [s.split(' #', 1)[0].strip() for s in path.read_text().splitlines()
            if s.strip() and not s.lstrip().startswith('#')]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--conf', required=True)
    args = ap.parse_args()
    manifest = load_routing_manifest(str(ROOT / 'config/routing.json'), str(ROOT / 'lists'))
    clash = yaml.safe_load((ROOT / 'clash/rule-providers.yaml').read_text())
    names = [r['name'] for r in manifest]
    assert list(clash['rule-providers']) == names
    assert {p.stem for p in (ROOT / 'clash').glob('*.list')} == set(names)
    total = 0
    for name in names:
        source = rules(ROOT / 'lists' / (name + '.list'))
        assert source == rules(ROOT / 'clash' / (name + '.list')), name
        total += len(source)
    assert clash['rules'] == [render_call(r, lambda name: name, clash=True) for r in manifest] + ['MATCH,Final']
    actual = []
    in_rules = False
    for line in Path(args.conf).read_text().splitlines():
        text = line.strip()
        if text.startswith('[') and text.endswith(']'):
            in_rules = text.lower() == '[rule]'
            continue
        if not in_rules or not text or text.startswith('#'):
            continue
        call = parse_ruleset_call(text)
        if call and call[0] not in ('SYSTEM', 'LAN'):
            actual.append((Path(call[0]).stem, call[1], tuple(Path(n).stem for n in call[3])))
    assert actual == [(r['name'], r['policy'], tuple(r.get('exclude_rulesets', []))) for r in manifest]
    # Managed DNS mappings must follow the same domain-owner order, including
    # proxy exceptions before broad DIRECT parents such as ChinaTLD.
    profile = Path(args.conf).read_text()
    begin, end = '# BEGIN managed routing DNS', '# END managed routing DNS'
    if begin in profile:
        managed = profile.split(begin,1)[1].split(end,1)[0]
        dns_owners = []
        for line in managed.splitlines():
            if line.startswith('RULE-SET:'):
                reference, servers = line.split(' = server:',1)
                owner = Path(reference.removeprefix('RULE-SET:')).stem
                entry = next(r for r in manifest if r['name']==owner)
                expected = ('system' if owner=='PrivateLAN' else
                            'https://223.5.5.5/dns-query,https://120.53.53.53/dns-query' if entry['policy']=='DIRECT' else
                            'https://8.8.8.8/dns-query,https://1.1.1.1/dns-query')
                assert servers == expected, owner
                dns_owners.append(owner)
        assert dns_owners == [r['name'] for r in manifest if r['kind']=='domain']
    assert not any('Fallback' in name for name in names)
    assert names.index('Microsoft') < names.index('MicrosoftCN')
    assert max(i for i,r in enumerate(manifest) if r['kind']=='domain') < min(i for i,r in enumerate(manifest) if r['kind']=='ip')
    dns = clash['dns']
    assert dns['enable'] and dns['enhanced-mode'] == 'fake-ip'
    assert not dns['use-system-hosts'] and not dns['use-hosts']
    assert dns['nameserver-policy'] == {'rule-set:PrivateLAN':'system'} and not dns['fallback']
    assert dns['direct-nameserver-follow-policy']
    assert 'rule-set:PrivateLAN' in dns['fake-ip-filter']
    assert not dns['proxy-server-nameserver-policy']
    for key in ['nameserver', 'default-nameserver', 'proxy-server-nameserver', 'direct-nameserver']:
        assert dns[key] and all(s.startswith('https://') for s in dns[key]), key
    assert all(s.endswith('#Proxy') for s in dns['nameserver'])
    assert all(s.endswith('#DIRECT') for s in dns['direct-nameserver'])
    assert clash['tun']['enable'] and clash['tun']['auto-route']
    assert set(clash['tun']['dns-hijack']) == {'any:53', 'tcp://any:53'}
    assert clash['sniffer']['enable'] and clash['sniffer']['parse-pure-ip']
    eng = engine.build_engine(args.conf, str(ROOT / 'lists'))
    witnesses = {
        'Google': ['mtalk.google.com', 'drive.usercontent.google.com', 'a.b.google.com',
                   'storage.googleapis.com', 'a.b.googleapis.com', 'a.b.googleusercontent.com',
                   'a.b.ggpht.com', 'a.b.gstatic.com'],
        'Meta': ['a.b.facebook.com', 'a.b.fbcdn.net', 'a.b.instagram.com',
                 'a.b.cdninstagram.com', 'a.b.whatsapp.net', 'a.b.meta.ai', 'a.b.threads.com'],
        'Twitter': ['a.b.x.com', 'a.b.twitter.com', 'a.b.twimg.com', 'a.b.t.co', 'a.b.x.ai', 'a.b.grok.com'],
        'Microsoft': ['outlook.cloud.microsoft', 'a.b.usercontent.microsoft', 'a.b.microsoftonline.com', 'account.microsoft.com', 'graph.microsoft.com', 'teams.microsoft.com', 'storage.msn.com',
                      'office.live.com', 'g.live.com', 'files.1drv.com', 'a.b.files.1drv.com',
                      'skyapi.onedrive.live.com', 'a.b.storage.live.com', 'd.docs.live.net',
                      'login.live.com', 'device.login.microsoftonline.com', 'aadcdn.msauth.net',
                      'a.msftauthimages.net', 'auth.gfx.ms', 'a.svc.ms'],
        'YouTube': ['youtubei.googleapis.com', 'yt3.googleusercontent.com'],
        'MicrosoftCN': ['download.microsoft.com', 'odc.officeapps.live.com',
                        'cdn.designerapp.osi.office.net', 'content.office.net',
                        'support.content.office.net'],
        'AI': ['api.claudemcpclient.com', 'openaiassets.blob.core.windows.net',
               'dashscope-intl.aliyuncs.com', 'coding-intl.dashscope.aliyuncs.com',
               'trial.ap-southeast-1.maas.aliyuncs.com', 'trae-api-sg.mchost.guru'],
        'AlibabaCN': ['qianwen.com', 'tongyi.com', 'qoder.cn', 'modelscope.cn',
                      'dashscope.aliyuncs.com', 'workspace.cn-beijing.maas.aliyuncs.com',
                      'bailian.console.alibabacloud.com', 'signin.alibabacloud.com'],
        'ByteDanceCN': ['coze.cn', 'cozeapp.net', 'cozecdn.com', 'trae-api-cn.mchost.guru'],
        'Domestic': ['lingyiwanwu.com', 'kimi.com', 'api.minimaxi.com'],
        'ModelDownloadCDN': ['us.aws.cdn.hf.co', 'cas-bridge.xethub.hf.co'],
        'DownloadCDN': ['dl.google.com', 'packages.microsoft.com'],
    }
    count = 0
    for owner, hosts in witnesses.items():
        for host in hosts:
            result = eng.match(host=host)
            assert result['source'] == owner + '.list', (host, result)
            assert not result['dns_leak'], host
            count += 1
    for host in ['notgoogle.com', 'google.com.example.org', 'notfacebook.com',
                 'facebook.com.example.org', 'notwitter.com', 'x.com.example.org',
                 'notmicrosoft.com', 'microsoft.com.example.org', 'a.b.blob.core.windows.net',
                 'unknown.microsoft.com', 'unknown.live.com', 'unknown.office.com', 'unknown.msn.com']:
        result = eng.match(host=host)
        assert result['source'] not in {n + '.list' for n in witnesses}, (host, result)
        count += 1
    print(f'PASS: {len(names)} providers; {total} exact rules; manifest order; DNS contract; {count} ownership witnesses')


if __name__ == '__main__':
    main()

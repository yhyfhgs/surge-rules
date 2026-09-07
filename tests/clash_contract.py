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


def rules(path):
    return [s.split(' #', 1)[0].strip() for s in path.read_text().splitlines()
            if s.strip() and not s.lstrip().startswith('#')]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--conf', required=True)
    args = ap.parse_args()
    manifest = json.loads((ROOT / 'config/routing.json').read_text())['rulesets']
    clash = yaml.safe_load((ROOT / 'clash/rule-providers.yaml').read_text())
    names = [r['name'] for r in manifest]
    assert list(clash['rule-providers']) == names
    assert {p.stem for p in (ROOT / 'clash').glob('*.list')} == set(names)
    total = 0
    for name in names:
        source = rules(ROOT / 'lists' / (name + '.list'))
        assert source == rules(ROOT / 'clash' / (name + '.list')), name
        total += len(source)
    assert clash['rules'] == [f"RULE-SET,{r['name']},{r['policy']},no-resolve" for r in manifest] + [
        'GEOIP,lan,DIRECT,no-resolve', 'GEOIP,CN,DIRECT,no-resolve', 'MATCH,Final']
    # Verify the actual conf's list order and policies, independently of its renderer.
    from urllib.parse import urlparse
    actual = []
    for line in Path(args.conf).read_text().splitlines():
        parts = line.strip().split(',')
        if parts[0] == 'RULE-SET' and parts[1] not in ('SYSTEM', 'LAN'):
            actual.append((Path(urlparse(parts[1]).path).stem, parts[2]))
    assert actual == [(r['name'], r['policy']) for r in manifest]
    assert not any('Fallback' in name for name in names)
    assert names.index('MicrosoftCN') < names.index('Microsoft')
    dns = clash['dns']
    assert dns['enable'] and dns['enhanced-mode'] == 'fake-ip'
    assert not dns['use-system-hosts'] and not dns['use-hosts']
    assert not dns['nameserver-policy'] and not dns['fallback']
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
        'Microsoft': ['outlook.cloud.microsoft', 'a.b.usercontent.microsoft', 'a.b.microsoftonline.com', 'a.b.microsoft.com', 'a.b.live.com', 'a.b.office.com', 'a.b.msn.com'],
        'YouTube': ['youtubei.googleapis.com', 'yt3.googleusercontent.com'],
        'MicrosoftCN': ['download.microsoft.com', 'office.live.com', 'g.live.com', 'odc.officeapps.live.com',
                        'cdn.designerapp.osi.office.net', 'content.office.net',
                        'support.content.office.net', 'files.1drv.com', 'a.b.files.1drv.com'],
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
                 'notmicrosoft.com', 'microsoft.com.example.org', 'a.b.blob.core.windows.net']:
        result = eng.match(host=host)
        assert result['source'] not in {n + '.list' for n in witnesses}, (host, result)
        count += 1
    print(f'PASS: {len(names)} providers; {total} exact rules; manifest order; DNS contract; {count} ownership witnesses')


if __name__ == '__main__':
    main()

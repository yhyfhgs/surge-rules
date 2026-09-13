#!/usr/bin/env python3
"""Prepare private Surge/Mihomo candidates without changing active profiles.

Only generated routing/DNS blocks and DIRECT members of proxy policy groups
are changed. Proxy definitions and certificate sections are verified unchanged.
"""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import yaml
from routing_manifest import load_routing_manifest
from render_surge_rules import render_rules, replace_rule_section, BASE_URL

ROOT = Path(__file__).resolve().parent.parent


def section(text, name):
    pattern = re.compile(r'(?m)^\[' + re.escape(name) + r'\][ \t]*$')
    hits = list(pattern.finditer(text))
    if len(hits) > 1:
        raise ValueError('duplicate profile section: ' + name)
    if not hits:
        return None
    start = hits[0].end()
    following = re.search(r'(?m)^\[[^\n]+\][ \t]*$', text[start:])
    end = start + following.start() if following else len(text)
    return start, end, text[start:end]


def replace_section(text, name, body):
    found = section(text, name)
    if found:
        start,end,_ = found
        return text[:start] + '\n' + body.strip('\n') + '\n\n' + text[end:]
    return text.rstrip() + '\n\n[' + name + ']\n' + body.strip('\n') + '\n'


def set_general(text, changes):
    body = section(text, 'General')[2]
    for key,value in changes.items():
        pattern = re.compile(r'(?m)^\s*' + re.escape(key) + r'\s*=.*$')
        if len(pattern.findall(body)) > 1:
            raise ValueError('duplicate General key: ' + key)
        line = key + ' = ' + value
        body = pattern.sub(line,body) if pattern.search(body) else body.rstrip()+'\n'+line+'\n'
    return replace_section(text,'General',body)


def reachable_groups(groups, roots):
    result, pending = set(), list(roots)
    while pending:
        name = pending.pop()
        if name in result or name not in groups:
            continue
        result.add(name)
        pending.extend(groups[name])
    return result


def surge_candidate(original, routing, base):
    result = replace_rule_section(original, render_rules(routing, base))
    public_roots = {r['policy'] for r in routing if r['policy'] not in ('DIRECT','REJECT')} | {routing.final['policy']}
    body = section(original,'Proxy Group')[2]
    groups = {}
    for raw in body.splitlines():
        if '=' in raw and not raw.lstrip().startswith('#'):
            name,value=raw.split('=',1)
            groups[name.strip()] = [v.strip() for v in value.split(',')[1:] if '=' not in v]
    reached = reachable_groups(groups,public_roots)
    lines, removed = [], 0
    for raw in body.splitlines():
        if '=' in raw and not raw.lstrip().startswith('#'):
            name,value=raw.split('=',1)
            parts=[v.strip() for v in value.split(',')]
            if name.strip() in reached and 'DIRECT' in parts[1:]:
                removed += parts[1:].count('DIRECT')
                parts=[parts[0]]+[v for v in parts[1:] if v!='DIRECT']
                if not any('=' not in v for v in parts[1:]):
                    raise ValueError('proxy-only group would have no members')
                raw=name.rstrip()+' = '+', '.join(parts)
        lines.append(raw)
    result=replace_section(result,'Proxy Group','\n'.join(lines))
    # The chosen encrypted resolvers are IP literals; all possible proxy servers
    # on their paths must also be literals to avoid the documented bootstrap loop.
    node_body=section(original,'Proxy')[2]
    nodes={}
    for raw in node_body.splitlines():
        if '=' in raw and not raw.lstrip().startswith('#'):
            name,value=raw.split('=',1);parts=[v.strip() for v in value.split(',')]
            if len(parts)>1:nodes[name.strip()]=parts[1]
    dns_groups=reached
    dns_members={m for name in dns_groups for m in groups[name] if m in nodes}
    if not dns_members:
        raise ValueError('cannot prove an acyclic DNS proxy path')
    for name in dns_members:
        ipaddress.ip_address(nodes[name])
    result=set_general(result,{
        'encrypted-dns-server':'https://8.8.8.8/dns-query, https://1.1.1.1/dns-query',
        'encrypted-dns-follow-outbound-mode':'true',
        'encrypted-dns-skip-cert-verification':'false',
        'use-local-host-item-for-proxy':'false',
    })
    host=section(result,'Host')
    host_body=host[2] if host else ''
    host_body=re.sub(r'(?ms)^# BEGIN managed routing DNS\n.*?^# END managed routing DNS\n?', '',host_body)
    managed=['# BEGIN managed routing DNS']
    for entry in routing:
        if entry['kind']=='domain':
            ref=base.rstrip('/')+'/'+entry['name']+'.list'
            servers=('system' if entry['name']=='PrivateLAN' else
                     'https://223.5.5.5/dns-query,https://120.53.53.53/dns-query' if entry['policy']=='DIRECT' else
                     'https://8.8.8.8/dns-query,https://1.1.1.1/dns-query')
            managed.append('RULE-SET:'+ref+' = server:'+servers)
    managed.append('# END managed routing DNS')
    result=replace_section(result,'Host',host_body.rstrip()+'\n'+'\n'.join(managed))
    mitm=section(result,'MITM')
    if mitm and re.search(r'(?m)^[ \t]*hostname[ \t]*=[ \t]*[^\s#]',mitm[2]):
        result=set_general(result,{'auto-quic-block':'true'})
    result=result.rstrip()+'\n'
    for name in ('Proxy','MITM'):
        before=section(original,name);after=section(result,name)
        if (before[2].rstrip() if before else None)!=(after[2].rstrip() if after else None):
            raise ValueError('protected profile section changed: '+name)
    return result,removed


def replace_yaml_sections(original, changes):
    # Preserve node and unrelated sections byte for byte, not merely YAML values.
    matches=list(re.finditer(r'(?m)^([A-Za-z][A-Za-z0-9_-]*):',original))
    blocks={m.group(1):(m.start(),matches[i+1].start() if i+1<len(matches) else len(original)) for i,m in enumerate(matches)}
    result=original
    for name,value in sorted(changes.items(),key=lambda item:blocks.get(item[0],(-1,-1))[0],reverse=True):
        block=yaml.safe_dump({name:value},allow_unicode=True,sort_keys=False).rstrip()+'\n\n'
        if name in blocks:
            start,end=blocks[name];result=result[:start]+block+result[end:]
        else:result=result.rstrip()+'\n\n'+block
    return result


def clash_candidate(original, routing, provider_dir=None, base_url=None):
    parsed=yaml.safe_load(original)
    generated=yaml.safe_load((ROOT/'clash/rule-providers.yaml').read_text())
    changes={key:generated[key] for key in ('mode','ipv6','geodata-mode','dns','sniffer','tun','rule-providers','rules')}
    if provider_dir:
        changes['rule-providers']={r['name']:{'type':'file','behavior':'classical','format':'text',
                                  'path':str(Path(provider_dir).resolve()/(r['name']+'.list'))} for r in routing}
    elif base_url:
        revision = re.search(r"@([0-9a-f]{40})/clash$",base_url)
        for name, provider in changes['rule-providers'].items():
            provider['url']=base_url.rstrip('/')+'/'+name+'.list'
            if revision:
                provider['path']='./rule-sets/surge-rules/'+revision.group(1)+'/'+name+'.list'
    groups={g['name']:g.get('proxies',[]) for g in parsed['proxy-groups']}
    roots={r['policy'] for r in routing if r['policy'] not in ('DIRECT','REJECT')}|{routing.final['policy']}
    reached=reachable_groups(groups,roots);removed=0
    newgroups=[]
    for group in parsed['proxy-groups']:
        group=dict(group)
        if group['name'] in reached and 'DIRECT' in group.get('proxies',[]):
            removed+=group['proxies'].count('DIRECT')
            group['proxies']=[m for m in group['proxies'] if m!='DIRECT']
            if not group['proxies']:raise ValueError('Clash proxy-only group would be empty')
        newgroups.append(group)
    if removed:changes['proxy-groups']=newgroups
    result=replace_yaml_sections(original,changes)
    checked=yaml.safe_load(result)
    assert checked['proxies']==parsed['proxies'],'private proxy definitions changed'
    for key in set(parsed)-set(changes):
        assert checked[key]==parsed[key], 'unrelated YAML section changed: '+key
    return result,removed


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--surge-in',required=True);ap.add_argument('--surge-out',required=True)
    ap.add_argument('--clash-in',required=True);ap.add_argument('--clash-out',required=True)
    ap.add_argument('--rules-base',default=BASE_URL);ap.add_argument('--clash-provider-dir')
    a=ap.parse_args();routing=load_routing_manifest(str(ROOT/'config/routing.json'),str(ROOT/'lists'))
    surge,sg=surge_candidate(Path(a.surge_in).read_text(),routing,a.rules_base)
    clash_base=a.rules_base.rsplit("/",1)[0]+"/clash" if a.rules_base.startswith("https://") else None
    clash,cg=clash_candidate(Path(a.clash_in).read_text(),routing,a.clash_provider_dir,clash_base)
    Path(a.surge_out).write_text(surge);Path(a.clash_out).write_text(clash)
    print(json.dumps({'rulesets':len(routing),'surge_direct_members_removed':sg,
                      'clash_direct_members_removed':cg,'protected_proxy_definitions':'unchanged',
                      'surge_sha256':hashlib.sha256(surge.encode()).hexdigest(),
                      'clash_sha256':hashlib.sha256(clash.encode()).hexdigest()}))


if __name__=='__main__':
    main()

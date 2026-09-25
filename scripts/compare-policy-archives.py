#!/usr/bin/env python3
"""Compare imported CSV definitions with a fresh export; no management writes."""
import argparse,csv,io,json,tarfile
from collections import Counter
from pathlib import Path

def read_archive(path):
    entries=[]
    def visit(stream,layer=None):
        with tarfile.open(fileobj=stream,mode='r:gz') as tar:
            for member in tar:
                if not member.isfile():continue
                if member.name.endswith('.tar.gz'):
                    parts=member.name.split('__')
                    visit(io.BytesIO(tar.extractfile(member).read()),'__'.join(parts[2:-1]))
                elif member.name.endswith('.csv'):
                    kind=member.name.split('__')[2].removeprefix('add-')
                    for row in csv.DictReader(io.TextIOWrapper(tar.extractfile(member),encoding='utf-8-sig')):
                        entries.append({'type':kind,'layer':layer,'fields':dict(row)})
    visit(io.BytesIO(Path(path).read_bytes()))
    return entries

def compare(expected,actual,suffix='',target_package=None):
    names={row['fields']['name']:row['fields']['name']+suffix for row in expected if row['fields'].get('name')}
    fields={'source','destination','service','members','include','except','original-source','original-destination','original-service','translated-source','translated-destination','translated-service','protected-scope','action','inline-layer','install-on','tags','name','nat-settings.install-on'}
    def normalize(row,source=False):
        data={key:value for key,value in row['fields'].items() if value!=''}
        if data.get('track.type','').lower()=='none':
            for key in ('track.per-session','track.per-connection','track.accounting','track.enable-firewall-session','track.alert'):data.pop(key,None)
        # API returns enums with display capitalization; compare case-insensitively.
        if 'track.type' in data:data['track.type']=data['track.type'].lower()
        for key,value in list(data.items()):
            if source and (key in fields or key.split('.')[0] in fields):data[key]=names.get(value,value)
            if data[key].lower() in ('true','false'):data[key]=data[key].lower()
        for field in ('members','source','destination','service','install-on','site-category','protected-scope','tags','blade','vpn'):
            keys=[key for key in data if key.startswith(field+'.') and key[len(field)+1:].isdigit()]
            if keys:
                data[field]=sorted(data.pop(key) for key in keys)
        return data
    failures=[];matched=set();unnamed=Counter()
    for row in expected:
        layer=row['layer']
        if layer:layer=target_package if row['type'].startswith('nat-') else names.get(layer,layer+suffix)
        wanted=normalize(row,True)
        candidates=[(i,r) for i,r in enumerate(actual) if i not in matched and r['type']==row['type'] and r['layer']==layer and (not wanted.get('name') or r['fields'].get('name')==wanted['name'])]
        if not candidates:
            failures.append({'type':row['type'],'layer':layer,'name':wanted.get('name'),'error':'missing definition'});continue
        i,got=candidates[0];matched.add(i);received=normalize(got)
        differences={key:{'expected':value,'actual':received.get(key)} for key,value in wanted.items() if received.get(key)!=value}
        if differences:failures.append({'type':row['type'],'layer':layer,'name':wanted.get('name'),'fields':differences})
    return {'matched':len(matched),'expected':len(expected),'differences':failures,'additional':dict(Counter(row['type'] for i,row in enumerate(actual) if i not in matched))}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('expected');p.add_argument('actual');p.add_argument('--suffix',default='');p.add_argument('--target-package');p.add_argument('--output')
    a=p.parse_args();result=compare(read_archive(a.expected),read_archive(a.actual),a.suffix,a.target_package);text=json.dumps(result,indent=2)
    if a.output:Path(a.output).write_text(text+'\n')
    print(text)
    raise SystemExit(1 if result['differences'] else 0)

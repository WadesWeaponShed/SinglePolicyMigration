#!/usr/bin/env python3
import csv,io,tarfile,pathlib,json
import argparse
parser=argparse.ArgumentParser(description='Build a lab-only full-coverage archive from clean Access and TP/HTTPS exports. Does not contact management.')
parser.add_argument('--access-archive',required=True,type=pathlib.Path)
parser.add_argument('--blades-archive',required=True,type=pathlib.Path)
parser.add_argument('--output',required=True,type=pathlib.Path)
parser.add_argument('--upper-source',default='CMA_LAB_Host_1')
parser.add_argument('--lower-source',default='CMA_LAB_Host_2')
args=parser.parse_args()
lab,standard,output=args.access_archive,args.blades_archive,args.output
def members(path):
 with tarfile.open(path) as t:return [(m.name,t.extractfile(m).read()) for m in t if m.isfile()]
def pack(entries):
 blob=io.BytesIO()
 with tarfile.open(fileobj=blob,mode='w:gz') as t:
  for name,data in entries:
   m=tarfile.TarInfo(name);m.size=len(data);t.addfile(m,io.BytesIO(data))
 return blob.getvalue()
def csvbytes(rows):
 s=io.StringIO();w=csv.DictWriter(s,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows);return s.getvalue().encode()
entries=members(lab)
entries.extend((name,data) for name,data in members(standard) if 'threat_layer' in name or 'add-threat-layer' in name)
nat=[{'name':'CMA_VERIFY_Upper','enabled':'false','method':'static','original-source':args.upper_source,'original-destination':'Any','original-service':'Any','translated-source':'Original','translated-destination':'Original','translated-service':'Original','install-on.0':'Policy Targets','__before_auto_rules':'true'}, {'name':'CMA_VERIFY_Lower','enabled':'false','method':'static','original-source':args.lower_source,'original-destination':'Any','original-service':'Any','translated-source':'Original','translated-destination':'Original','translated-service':'Original','install-on.0':'Policy Targets','__before_auto_rules':'false'}]
entries=[(name,pack([('version.txt',b'2.1'),('01____add-nat-rule__validation.csv',csvbytes(nat))]) if 'nat_layer' in name else data) for name,data in entries]
output.parent.mkdir(parents=True,exist_ok=True)
output.write_bytes(pack(entries));output.chmod(0o600)
print(output)

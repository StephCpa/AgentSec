#!/usr/bin/env python3
"""Optional figure renderer; requires matplotlib, separate from ledger dependencies."""
import argparse
import json
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

parser=argparse.ArgumentParser()
parser.add_argument('report',type=Path);parser.add_argument('output',type=Path)
args=parser.parse_args();data=json.loads(args.report.read_text())
rows=[x for x in data['poll_trials'] if x['mode']=='new']
fig,axes=plt.subplots(1,3,figsize=(14,4.5),layout='constrained')
blue='#2463A6';orange='#C86D22'
axes[0].plot([r['history_polls'] for r in rows],[r['before']['image_bytes']/1024 for r in rows],marker='o',color=blue)
axes[0].set(xlabel='Previously committed POLL requests',ylabel='Current image (KiB)',title='Current state grows with history')
axes[1].plot([r['history_polls'] for r in rows],[r['growth']['cas_image_bytes']/2**20 for r in rows],marker='o',color=blue)
axes[1].set(xlabel='New POLL requests',ylabel='Cumulative CAS image payload (MiB)',title='Each request copies the whole image')
for offset,kind,color in [(-.18,'count',blue),(.18,'histogram',orange)]:
 rows=[r for r in data['query_trials'] if r['kind']==kind]
 bars=axes[2].bar([i+offset for i in range(3)],[r['execution']['cas_image_bytes']/2**20 for r in rows],width=.36,label=kind,color=color)
 axes[2].bar_label(bars,fmt='%.1f',fontsize=8,padding=3)
axes[2].set(xticks=range(3),xticklabels=['None','Every slot','Every 8 slots'],xlabel='POLL cadence during query',ylabel='Execution CAS image payload (MiB)',title='Polling amplifies query persistence cost')
axes[2].legend(frameon=False,loc='upper right');axes[2].margins(y=.18)
for ax in axes:
 ax.spines[['top','right']].set_visible(False);ax.grid(axis='y',alpha=.2);ax.set_axisbelow(True)
fig.suptitle('AgentSec synthetic local persistence measurements | N=3, histogram B=4 | no TLS traffic',fontsize=12)
args.output.parent.mkdir(parents=True,exist_ok=True);fig.savefig(args.output,dpi=170);plt.close(fig)

from __future__ import annotations
import gc,gzip,json,os,random,struct,time
from pathlib import Path
import numpy as np
import torch
from torch import nn
import torch.nn.functional as F

SEED=20260929
random.seed(SEED); np.random.seed(SEED); torch.manual_seed(SEED)
torch.set_num_threads(max(2,min(4,os.cpu_count() or 2)))
OUT=Path('flybrain_ai/results_v3_fast'); OUT.mkdir(parents=True,exist_ok=True)
SRC=Path('flybrain-src')
meta=json.loads((SRC/'data/neuron_meta.json').read_text())
raw=gzip.decompress((SRC/'data/connectome.bin.gz').read_bytes())
n,e=struct.unpack_from('<II',raw,0)
edge_dt=np.dtype([('pre','<u4'),('post','<u4'),('weight','<f4')]); edges=np.frombuffer(raw,dtype=edge_dt,count=e,offset=8)
mb=np.frombuffer(raw,dtype=np.uint8,count=n*3,offset=8+e*12).reshape(n,3)
group=(mb[:,1].astype(np.uint16)|(mb[:,2].astype(np.uint16)<<8)).astype(np.int64)
pre=edges['pre'].astype(np.int64,copy=False); post=edges['post'].astype(np.int64,copy=False)
w=edges['weight'].astype(np.float32,copy=True); w*=0.15/(float(np.max(np.abs(w))) or 1.0)
counts=np.bincount(pre,minlength=n); rowptr=np.empty(n+1,np.int64); rowptr[0]=0; np.cumsum(counts,out=rowptr[1:])
gnames=[g['name'] for g in meta['groups']]
assert n==139255 and e==meta['edge_count'] and len(gnames)==63

def sim(gs,ticks=16,intensity=1.35):
    V=np.zeros(n,np.float32); fired=np.zeros(n,bool); ref=np.zeros(n,np.uint8); stim=[]
    for g in gs:
        idx=np.flatnonzero(group==g)
        if len(idx):
            stride=max(1,len(idx)//384); stim.extend(idx[::stride][:384].tolist())
    stim=np.asarray(sorted(set(stim)),np.int64); traces=[]
    for t in range(ticks):
        m=ref>0; ref[m]-=1; V[m]=0; V[~m]*=.95
        if t<8:
            valid=stim[ref[stim]==0]; V[valid]+=intensity
        for i in np.flatnonzero(fired):
            a,b=int(rowptr[i]),int(rowptr[i+1])
            if b>a: np.add.at(V,post[a:b],w[a:b])
        fired[:]=False; now=(ref==0)&(V>=1.0); fired[now]=True; V[now]=0; ref[now]=3
        traces.append(np.bincount(group[now],minlength=len(gnames)).astype(np.float32))
    tr=np.stack(traces); pop=np.bincount(group,minlength=len(gnames)).astype(np.float32); pop[pop==0]=1
    s=.7*tr[-6:].sum(0)/pop+.3*tr.sum(0)/pop
    if s.max()>0:s/=s.max()
    return s.astype(np.float32)
scenarios=[([6,32,37],'food-seeking'),([10,11],'touch-alert'),([0,2],'visual-tracking'),([14],'warmth'),([15],'cooling'),([6,10,0],'multisensory-exploration')]
X0=torch.tensor(np.stack([sim(gs) for gs,_ in scenarios]),dtype=torch.float32); labels=[x[1] for x in scenarios]
aug_x=[];aug_y=[]
for cls,x in enumerate(X0):
    aug_x.append(x);aug_y.append(cls)
    for _ in range(63):
        z=(x*(.88+.24*random.random())+torch.randn_like(x)*.035).clamp(0,1);aug_x.append(z);aug_y.append(cls)
X=torch.stack(aug_x);Y=torch.tensor(aug_y)
class Bridge(nn.Module):
    def __init__(self):
        super().__init__();self.net=nn.Sequential(nn.Linear(63,96),nn.GELU(),nn.Linear(96,48),nn.GELU(),nn.Linear(48,6))
    def forward(self,x):return self.net(x)
bridge=Bridge();opt=torch.optim.AdamW(bridge.parameters(),lr=4e-3)
for step in range(180):
    logits=bridge(X);loss=F.cross_entropy(logits,Y);opt.zero_grad();loss.backward();opt.step()
bridge.eval();probe=(.58*X0[1]+.42*X0[2]).clamp(0,1)
with torch.no_grad():
    p=torch.softmax(bridge(probe[None]),-1)[0];vals,ids=torch.topk(p,3)
pred=[{'label':labels[int(i)],'prob':float(v)} for v,i in zip(vals,ids)]
top=np.argsort(probe.numpy())[::-1][:4];active=[(gnames[int(i)],float(probe[int(i)])) for i in top if probe[int(i)]>0]
print('PROBE',pred,active,flush=True)
torch.save({'state_dict':bridge.state_dict(),'labels':labels,'group_names':gnames},OUT/'semantic_bridge_fast.pt')

del X,Y;gc.collect()
from diffusers import StableDiffusionXLPipeline,DPMSolverMultistepScheduler
name='segmind/SSD-1B';t0=time.time()
pipe=StableDiffusionXLPipeline.from_pretrained(name,torch_dtype=torch.float32,use_safetensors=True,low_cpu_mem_usage=True)
pipe.scheduler=DPMSolverMultistepScheduler.from_config(pipe.scheduler.config,use_karras_sigmas=True)
pipe.to('cpu');pipe.set_progress_bar_config(disable=False);pipe.enable_attention_slicing('max');pipe.enable_vae_slicing();pipe.enable_vae_tiling()
print('LOAD_SEC',time.time()-t0,flush=True)
sem=', '.join(f"{x['label']} {x['prob']:.2f}" for x in pred[:2]);cir=', '.join(a.replace('_',' ') for a,_ in active)
prompt=("ultra detailed scientific macro visualization of a Drosophila fruit fly brain connectome inside a translucent fly head, "
        "thousands of fine glowing neural pathways and synapses, realistic microscopy fused with cinematic laboratory photography, dark background, "
        "volumetric light, high contrast, anatomically inspired neural wiring, photorealistic, no text, no labels, "
        f"neural controller state {sem}, active sensory circuits {cir}, tactile and visual tracking pathways strongly illuminated")
neg='words, text, labels, watermark, logo, blurry, low resolution, cartoon, flat illustration, malformed fly'
g=torch.Generator('cpu').manual_seed(SEED);t=time.time()
with torch.no_grad():
    img=pipe(prompt=prompt,negative_prompt=neg,num_inference_steps=6,guidance_scale=7.5,height=512,width=512,generator=g).images[0]
img.save(OUT/'ssd1b_flybrain_fast.png');print('GEN_SEC',time.time()-t,flush=True)
result={'version':'v3-fast-float32','connectome':{'neurons':n,'edges':e,'groups':63},'bridge_probe':pred,'active_groups':active,'model':name,'dtype':'float32','size':[512,512],'steps':6,'prompt':prompt,'file':'ssd1b_flybrain_fast.png'}
(OUT/'results_v3_fast.json').write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding='utf-8')
print('RESULT',json.dumps(result,ensure_ascii=False),flush=True)

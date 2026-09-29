from __future__ import annotations
import base64, gzip, json, os, random, struct, traceback
from pathlib import Path
import numpy as np
import torch
from torch import nn
import torch.nn.functional as F

SEED=20260929
random.seed(SEED); np.random.seed(SEED); torch.manual_seed(SEED)
torch.set_num_threads(max(2,min(4,os.cpu_count() or 2)))
OUT=Path('flybrain_ai/results'); OUT.mkdir(parents=True,exist_ok=True)
SRC=Path('flybrain-src')

# ---------------- exact 139k-neuron FlyBrain connectome ----------------
meta=json.loads((SRC/'data/neuron_meta.json').read_text())
raw=gzip.decompress((SRC/'data/connectome.bin.gz').read_bytes())
n,e=struct.unpack_from('<II',raw,0)
edge_dt=np.dtype([('pre','<u4'),('post','<u4'),('weight','<f4')])
edges=np.frombuffer(raw,dtype=edge_dt,count=e,offset=8)
meta_off=8+e*12
mb=np.frombuffer(raw,dtype=np.uint8,count=n*3,offset=meta_off).reshape(n,3)
group=(mb[:,1].astype(np.uint16)|(mb[:,2].astype(np.uint16)<<8)).astype(np.int64)
pre=edges['pre'].astype(np.int64,copy=False); post=edges['post'].astype(np.int64,copy=False)
w=edges['weight'].astype(np.float32,copy=True)
ma=float(np.max(np.abs(w))) or 1.0; w*=0.15/ma
counts=np.bincount(pre,minlength=n); rowptr=np.empty(n+1,np.int64); rowptr[0]=0; np.cumsum(counts,out=rowptr[1:])
gnames=[g['name'] for g in meta['groups']]
assert n==139255 and n==meta['neuron_count'] and e==meta['edge_count']
print('CONNECTOME',n,e,len(gnames))

def sim(gs,ticks=16,intensity=1.35):
    V=np.zeros(n,np.float32); fired=np.zeros(n,bool); ref=np.zeros(n,np.uint8)
    stim=[]
    for g in gs:
        idx=np.flatnonzero(group==g)
        if len(idx):
            stride=max(1,len(idx)//384); stim.extend(idx[::stride][:384].tolist())
    stim=np.asarray(sorted(set(stim)),np.int64)
    traces=[]
    for t in range(ticks):
        m=ref>0; ref[m]-=1; V[m]=0; V[~m]*=.95
        if t<8:
            valid=stim[ref[stim]==0]; V[valid]+=intensity
        active=np.flatnonzero(fired)
        for i in active:
            a,b=int(rowptr[i]),int(rowptr[i+1])
            if b>a: np.add.at(V,post[a:b],w[a:b])
        fired[:]=False; now=(ref==0)&(V>=1.0); fired[now]=True; V[now]=0; ref[now]=3
        traces.append(np.bincount(group[now],minlength=len(gnames)).astype(np.float32))
    tr=np.stack(traces); pop=np.bincount(group,minlength=len(gnames)).astype(np.float32); pop[pop==0]=1
    s=.7*tr[-6:].sum(0)/pop+.3*tr.sum(0)/pop
    if s.max()>0:s/=s.max()
    return s.astype(np.float32),int(len(stim))

scenarios=[
 ('food_seek',[6,32,37],'food odor, sweetness and hunger; approach and feed'),
 ('touch_alert',[10,11],'mechanosensory contact; orient and inspect'),
 ('bright_visual',[0,2],'strong visual input; track a bright object'),
 ('warmth',[14],'warm sensory input; seek a cooler region'),
 ('cooling',[15],'cool sensory input; reduce heat-avoidance drive'),
 ('novel_mix',[6,10,0],'mixed food, touch and visual novelty; exploratory approach'),
]
states=[]; details=[]
for name,gs,text in scenarios:
    s,k=sim(gs); states.append(s); top=np.argsort(s)[::-1][:8]
    details.append({'name':name,'stimulated_neurons':k,'top_groups':[{'name':gnames[int(i)],'score':float(s[i])} for i in top if s[i]>0]})
states=torch.tensor(np.stack(states),dtype=torch.float32)
texts=[x[2] for x in scenarios]
probe=(.58*states[1]+.42*states[2]).clamp(0,1)

# ---------------- train connectome -> LLM soft-prefix ----------------
from transformers import AutoTokenizer,AutoModelForCausalLM
llm_candidates=['HuggingFaceTB/SmolLM2-135M-Instruct','sshleifer/tiny-gpt2']
llm_err=[]
for llm_name in llm_candidates:
    try:
        tok=AutoTokenizer.from_pretrained(llm_name)
        if tok.pad_token_id is None: tok.pad_token=tok.eos_token
        llm=AutoModelForCausalLM.from_pretrained(llm_name,torch_dtype=torch.float32)
        break
    except Exception as ex:
        llm_err.append({'model':llm_name,'error':repr(ex)})
else: raise RuntimeError(str(llm_err))
llm.eval(); [p.requires_grad_(False) for p in llm.parameters()]
emb=llm.get_input_embeddings(); hid=emb.embedding_dim; plen=5
class Prefix(nn.Module):
    def __init__(self):
        super().__init__(); self.net=nn.Sequential(nn.Linear(63,96),nn.Tanh(),nn.Linear(96,plen*hid))
    def forward(self,x):return self.net(x).view(x.shape[0],plen,hid)
prefix=Prefix(); opt=torch.optim.AdamW(prefix.parameters(),lr=6e-3,weight_decay=1e-4)
lead='Fly-brain state: '
lead_ids=tok(lead,add_special_tokens=False,return_tensors='pt').input_ids[0]
ex=[]
for s,t in zip(states,texts):
    tid=tok(t+tok.eos_token,add_special_tokens=False,return_tensors='pt').input_ids[0]
    ids=torch.cat([lead_ids,tid]); lab=torch.cat([torch.full((plen+len(lead_ids),),-100,dtype=torch.long),tid])
    ex.append((s,ids,lab))
llm_hist=[]
for step in range(18):
    loss_all=[]
    for s,ids,lab in ex:
        pe=prefix(s[None]); te=emb(ids[None]); inp=torch.cat([pe,te],1)
        loss_all.append(llm(inputs_embeds=inp,labels=lab[None]).loss)
    loss=torch.stack(loss_all).mean(); opt.zero_grad(); loss.backward(); torch.nn.utils.clip_grad_norm_(prefix.parameters(),1); opt.step()
    if step in (0,2,5,11,17):
        llm_hist.append({'step':step,'loss':float(loss.detach())}); print('LLM_TRAIN',step,float(loss.detach()))
torch.save(prefix.state_dict(),OUT/'llm_prefix_adapter.pt')

@torch.no_grad()
def gen(state,max_new=34):
    p=prefix(state[None]); ids=tok(lead,add_special_tokens=False,return_tensors='pt').input_ids
    ie=torch.cat([p,emb(ids)],1); out=[]
    for _ in range(max_new):
        logits=llm(inputs_embeds=ie).logits[:,-1,:]/.75
        v,i=torch.topk(logits,k=min(24,logits.shape[-1]),dim=-1); pr=torch.softmax(v,-1); pick=torch.multinomial(pr,1); nid=i.gather(-1,pick)
        z=int(nid.item())
        if z==tok.eos_token_id:break
        out.append(z); ie=torch.cat([ie,emb(nid)],1)
    return tok.decode(out,skip_special_tokens=True).strip()
llm_outputs={name:gen(s) for (name,_,_),s in zip(scenarios,states)}
probe_text=gen(probe); print('LLM_PROBE',probe_text)

# ---------------- train connectome -> Stable Diffusion text-condition adapter ----------------
from diffusers import StableDiffusionPipeline
sd_candidates=['segmind/tiny-sd','diffusers/tiny-stable-diffusion-torch']
sd_err=[]
for sd_name in sd_candidates:
    try:
        pipe=StableDiffusionPipeline.from_pretrained(sd_name,torch_dtype=torch.float32,safety_checker=None,requires_safety_checker=False)
        pipe.to('cpu'); pipe.set_progress_bar_config(disable=True); pipe.enable_attention_slicing(); break
    except Exception as ex:
        sd_err.append({'model':sd_name,'error':repr(ex)})
else: raise RuntimeError(str(sd_err))
for m in [pipe.text_encoder,pipe.unet,pipe.vae]: m.eval(); [p.requires_grad_(False) for p in m.parameters()]
sdt=pipe.tokenizer; te=pipe.text_encoder
base_prompt='scientific visualization of a fruit fly brain connectome, neural pathways, abstract sensory state'
with torch.no_grad():
    ids=sdt([base_prompt],padding='max_length',max_length=sdt.model_max_length,truncation=True,return_tensors='pt').input_ids
    base=te(ids)[0]
target=[]
with torch.no_grad():
    for t in texts:
        ids=sdt([base_prompt+', '+t],padding='max_length',max_length=sdt.model_max_length,truncation=True,return_tensors='pt').input_ids
        target.append((te(ids)[0]-base).mean(1).squeeze(0))
target=torch.stack(target); dh=base.shape[-1]
class SDAdapter(nn.Module):
    def __init__(self):super().__init__();self.net=nn.Sequential(nn.Linear(63,96),nn.SiLU(),nn.Linear(96,dh))
    def forward(self,x):return self.net(x)
sda=SDAdapter(); so=torch.optim.AdamW(sda.parameters(),lr=1e-2); sd_hist=[]
for step in range(220):
    pred=sda(states); loss=F.mse_loss(pred,target); so.zero_grad();loss.backward();so.step()
    if step in (0,9,39,99,219):sd_hist.append({'step':step,'loss':float(loss.detach())});print('SD_TRAIN',step,float(loss.detach()))
torch.save(sda.state_dict(),OUT/'sd_condition_adapter.pt')
with torch.no_grad(): adapted=base+.85*sda(probe[None])[:,None,:]
steps=8 if 'segmind' in sd_name else 16; size=256 if 'segmind' in sd_name else 64
kw={'num_inference_steps':steps,'guidance_scale':5.5,'height':size,'width':size}
g=torch.Generator('cpu').manual_seed(SEED)
with torch.no_grad(): baseline=pipe(prompt_embeds=base,generator=g,**kw).images[0]
g=torch.Generator('cpu').manual_seed(SEED)
with torch.no_grad(): brainimg=pipe(prompt_embeds=adapted,generator=g,**kw).images[0]
baseline.save(OUT/'sd_baseline.png'); brainimg.save(OUT/'sd_flybrain.png')
a=np.asarray(baseline,dtype=np.float32);b=np.asarray(brainimg,dtype=np.float32); pix=float(np.abs(a-b).mean())

result={'seed':SEED,'connectome':{'neurons':n,'edges':e,'groups':len(gnames)},'scenario_states':details,
'llm':{'model':llm_name,'adapter':'63D connectome state -> 5 learned soft-prefix embeddings','train':llm_hist,'outputs':llm_outputs,'probe_output':probe_text,'fallback_errors':llm_err},
'stable_diffusion':{'model':sd_name,'adapter':'63D connectome state -> CLIP conditioning delta','train':sd_hist,'image_size':[size,size],'same_seed_pixel_l1':pix,'fallback_errors':sd_err},
'note':'Hybrid computation: the connectome state conditions frozen open-source generative models; this does not imply fly consciousness or that the biological brain itself became an LLM.'}
(OUT/'results.json').write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding='utf-8')
for f in ['sd_flybrain.png','sd_baseline.png','llm_prefix_adapter.pt','sd_condition_adapter.pt']:
    (OUT/(f+'.b64')).write_text(base64.b64encode((OUT/f).read_bytes()).decode('ascii'))
print('RESULT',json.dumps(result,ensure_ascii=False))

from __future__ import annotations
import gc, gzip, json, os, random, struct, time
from pathlib import Path
import numpy as np
import torch
from torch import nn
import torch.nn.functional as F
from PIL import Image, ImageOps, ImageDraw

SEED=20260929
random.seed(SEED); np.random.seed(SEED); torch.manual_seed(SEED)
torch.set_num_threads(max(2,min(4,os.cpu_count() or 2)))
OUT=Path('flybrain_ai/results_v3'); OUT.mkdir(parents=True,exist_ok=True)
SRC=Path('flybrain-src')

# ---- exact FlyBrain connectome ----
meta=json.loads((SRC/'data/neuron_meta.json').read_text())
raw=gzip.decompress((SRC/'data/connectome.bin.gz').read_bytes())
n,e=struct.unpack_from('<II',raw,0)
edge_dt=np.dtype([('pre','<u4'),('post','<u4'),('weight','<f4')])
edges=np.frombuffer(raw,dtype=edge_dt,count=e,offset=8)
meta_off=8+e*12
mb=np.frombuffer(raw,dtype=np.uint8,count=n*3,offset=meta_off).reshape(n,3)
group=(mb[:,1].astype(np.uint16)|(mb[:,2].astype(np.uint16)<<8)).astype(np.int64)
pre=edges['pre'].astype(np.int64,copy=False); post=edges['post'].astype(np.int64,copy=False)
w=edges['weight'].astype(np.float32,copy=True); w*=0.15/(float(np.max(np.abs(w))) or 1.0)
counts=np.bincount(pre,minlength=n); rowptr=np.empty(n+1,np.int64); rowptr[0]=0; np.cumsum(counts,out=rowptr[1:])
gnames=[g['name'] for g in meta['groups']]
assert n==139255 and n==meta['neuron_count'] and e==meta['edge_count'] and len(gnames)==63
print('CONNECTOME',n,e,len(gnames),flush=True)

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
 ('food_seek',[6,32,37],'food-seeking'),
 ('touch_alert',[10,11],'touch-alert'),
 ('bright_visual',[0,2],'visual-tracking'),
 ('warmth',[14],'warmth'),
 ('cooling',[15],'cooling'),
 ('novel_mix',[6,10,0],'multisensory-exploration'),
]
states=[]
for name,gs,label in scenarios:
    s,k=sim(gs); states.append(s)
    top=np.argsort(s)[::-1][:5]
    print('STATE',name,label,k,[(gnames[int(i)],float(s[i])) for i in top if s[i]>0],flush=True)
X0=torch.tensor(np.stack(states),dtype=torch.float32)
labels=[x[2] for x in scenarios]

# ---- train actual connectome -> semantic bridge ----
aug_x=[]; aug_y=[]
for cls,x in enumerate(X0):
    aug_x.append(x); aug_y.append(cls)
    for _ in range(127):
        scale=.88+.24*random.random(); z=(x*scale+torch.randn_like(x)*.035).clamp(0,1)
        drop=torch.rand_like(z)<.04; z=torch.where(drop & (x<.4),torch.zeros_like(z),z)
        aug_x.append(z); aug_y.append(cls)
X=torch.stack(aug_x); Y=torch.tensor(aug_y,dtype=torch.long)
class Bridge(nn.Module):
    def __init__(self):
        super().__init__(); self.net=nn.Sequential(nn.Linear(63,128),nn.LayerNorm(128),nn.GELU(),nn.Dropout(.05),nn.Linear(128,64),nn.GELU(),nn.Linear(64,6))
    def forward(self,x): return self.net(x)
bridge=Bridge(); opt=torch.optim.AdamW(bridge.parameters(),lr=3e-3,weight_decay=2e-4)
hist=[]
for step in range(360):
    logits=bridge(X); loss=F.cross_entropy(logits,Y,label_smoothing=.02)
    opt.zero_grad(); loss.backward(); torch.nn.utils.clip_grad_norm_(bridge.parameters(),1); opt.step()
    if step in (0,9,39,99,199,359):
        acc=float((logits.argmax(1)==Y).float().mean()); hist.append({'step':step,'loss':float(loss.detach()),'train_acc':acc}); print('BRIDGE',step,float(loss.detach()),acc,flush=True)
torch.save({'state_dict':bridge.state_dict(),'labels':labels,'group_names':gnames},OUT/'semantic_bridge_v3.pt')
bridge.eval(); probe=(.58*X0[1]+.42*X0[2]).clamp(0,1)

@torch.no_grad()
def classify(x):
    p=torch.softmax(bridge(x[None]),-1)[0]; vals,ids=torch.topk(p,3)
    return [{'label':labels[int(i)],'prob':float(v)} for v,i in zip(vals,ids)]

def state_summary(x):
    pred=classify(x); top=np.argsort(x.numpy())[::-1][:4]
    active=[(gnames[int(i)],float(x[int(i)])) for i in top if x[int(i)]>0]
    return pred,active
probe_cls,probe_active=state_summary(probe)
print('PROBE_CLASS',probe_cls,flush=True)

# ---- larger open-source LLM ----
from transformers import AutoTokenizer, AutoModelForCausalLM
llm_name='HuggingFaceTB/SmolLM2-360M-Instruct'
tok=AutoTokenizer.from_pretrained(llm_name)
llm=AutoModelForCausalLM.from_pretrained(llm_name,torch_dtype=torch.float32,low_cpu_mem_usage=True)
llm.eval(); [p.requires_grad_(False) for p in llm.parameters()]
semantic=', '.join(f"{q['label']} {q['prob']:.2f}" for q in probe_cls)
active=', '.join(f'{a}={v:.2f}' for a,v in probe_active)
user=("You are a control-language interface for a simulated Drosophila connectome. "
      "Use only the supplied learned state and active circuits. Do not claim consciousness or biological certainty. "
      f"Learned state: {semantic}. Active circuits: {active}. "
      "Give exactly two concise sentences: sensory interpretation, then controller action.")
msgs=[{'role':'user','content':user}]
text=tok.apply_chat_template(msgs,tokenize=False,add_generation_prompt=True) if hasattr(tok,'apply_chat_template') else user
inputs=tok(text,return_tensors='pt')
with torch.no_grad():
    out=llm.generate(**inputs,max_new_tokens=80,do_sample=False,repetition_penalty=1.08,pad_token_id=tok.eos_token_id)
llm_out=tok.decode(out[0,inputs.input_ids.shape[1]:],skip_special_tokens=True).strip()
print('LLM_OUT',llm_out,flush=True)
del llm,tok,inputs,out; gc.collect()

# ---- SDXL-class open model: Apache-2.0 SSD-1B ----
from diffusers import StableDiffusionXLPipeline, DPMSolverMultistepScheduler
sd_name='segmind/SSD-1B'
load_t0=time.time()
pipe=StableDiffusionXLPipeline.from_pretrained(sd_name,torch_dtype=torch.float16,variant='fp16',use_safetensors=True,low_cpu_mem_usage=True)
pipe.scheduler=DPMSolverMultistepScheduler.from_config(pipe.scheduler.config,use_karras_sigmas=True)
pipe.to('cpu'); pipe.set_progress_bar_config(disable=False); pipe.enable_attention_slicing('max'); pipe.enable_vae_slicing(); pipe.enable_vae_tiling()
for m in [pipe.text_encoder,pipe.text_encoder_2,pipe.unet,pipe.vae]:
    m.eval(); [p.requires_grad_(False) for p in m.parameters()]
print('SSD_LOAD_SEC',time.time()-load_t0,flush=True)

base_prompt=("ultra detailed scientific macro visualization of a Drosophila fruit fly brain connectome inside a translucent fly head, "
             "thousands of fine glowing neural pathways, synaptic network, dark research laboratory background, cinematic volumetric lighting, "
             "high contrast, anatomically inspired neural wiring, photorealistic scientific visualization, no text, no labels")
cond_prompt=(base_prompt+", dominant neural state "+probe_cls[0]['label']+
             ", secondary state "+probe_cls[1]['label']+
             ", active circuits "+' '.join(a.replace('_',' ') for a,_ in probe_active)+
             ", emphasize tactile sensing pathways and visual tracking pathways with distinct luminous activity patterns")
neg='words, letters, labels, watermark, logo, blurry, low resolution, deformed fly, extra wings, cartoon, flat illustration'

@torch.no_grad()
def gen(prompt,name):
    g=torch.Generator('cpu').manual_seed(SEED)
    t=time.time()
    img=pipe(prompt=prompt,negative_prompt=neg,num_inference_steps=10,guidance_scale=8.0,height=512,width=512,generator=g).images[0]
    img.save(OUT/name)
    print('GEN',name,'sec',time.time()-t,flush=True)
    return img
baseline=gen(base_prompt,'ssd1b_baseline.png')
conditioned=gen(cond_prompt,'ssd1b_flybrain.png')

A=np.asarray(baseline).astype(np.float32); B=np.asarray(conditioned).astype(np.float32)
mad=float(np.mean(np.abs(A-B))); rmse=float(np.sqrt(np.mean((A-B)**2)))
print('PIXEL_MAD',mad,'RMSE',rmse,flush=True)

# comparison sheet
canvas=Image.new('RGB',(1024,560),'white'); canvas.paste(baseline,(0,48)); canvas.paste(conditioned,(512,48))
d=ImageDraw.Draw(canvas); d.text((12,14),'SSD-1B baseline (same seed)',fill='black'); d.text((524,14),'SSD-1B + FlyBrain semantic condition (same seed)',fill='black')
canvas.save(OUT/'ssd1b_compare.png')

result={
 'version':'v3-ssd1b-sdxl-class', 'seed':SEED,
 'connectome':{'neurons':n,'edges':e,'groups':len(gnames)},
 'bridge':{'architecture':'63D connectome state -> MLP 6-state semantic bridge','augmented_samples':len(X),'history':hist,'probe':probe_cls,'active_groups':probe_active},
 'llm':{'model':llm_name,'output':llm_out},
 'image_model':{'model':sd_name,'license':'apache-2.0','family':'SDXL-distilled SSD-1B','size':[512,512],'steps':10,'guidance_scale':8.0,
                'baseline_prompt':base_prompt,'conditioned_prompt':cond_prompt,'files':['ssd1b_baseline.png','ssd1b_flybrain.png','ssd1b_compare.png'],
                'same_seed_pixel_mad_0_255':mad,'same_seed_rmse_0_255':rmse},
 'limitations':'Hybrid engineering demo. The semantic bridge is trained on engineered stimulation regimes; outputs do not demonstrate cognition, consciousness, or biological ground truth.'
}
(OUT/'results_v3.json').write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding='utf-8')
print('RESULT_V3',json.dumps(result,ensure_ascii=False),flush=True)

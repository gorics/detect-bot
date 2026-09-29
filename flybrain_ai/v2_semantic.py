from __future__ import annotations
import base64, gzip, json, os, random, struct, math
from pathlib import Path
import numpy as np
import torch
from torch import nn
import torch.nn.functional as F

SEED=20260929
random.seed(SEED); np.random.seed(SEED); torch.manual_seed(SEED)
torch.set_num_threads(max(2,min(4,os.cpu_count() or 2)))
OUT=Path('flybrain_ai/results_v2'); OUT.mkdir(parents=True,exist_ok=True)
SRC=Path('flybrain-src')

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
max_abs=float(np.max(np.abs(w))) or 1.0; w*=0.15/max_abs
counts=np.bincount(pre,minlength=n); rowptr=np.empty(n+1,np.int64); rowptr[0]=0; np.cumsum(counts,out=rowptr[1:])
gnames=[g['name'] for g in meta['groups']]
assert n==139255 and n==meta['neuron_count'] and e==meta['edge_count'] and len(gnames)==63
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
 ('food_seek',[6,32,37],'food-seeking','food odor + sweet taste + hunger drive; likely approach/feeding-related state'),
 ('touch_alert',[10,11],'touch-alert','mechanosensory contact; orienting/inspection-related state'),
 ('bright_visual',[0,2],'visual-tracking','strong visual input; tracking/orienting-related state'),
 ('warmth',[14],'warmth','warm sensory input; heat-response-related state'),
 ('cooling',[15],'cooling','cool sensory input; cooling-response-related state'),
 ('novel_mix',[6,10,0],'multisensory-exploration','food odor + touch + visual novelty; exploratory multisensory state'),
]
states=[]; state_details=[]
for name,gs,label,desc in scenarios:
    s,k=sim(gs); states.append(s); top=np.argsort(s)[::-1][:8]
    state_details.append({'name':name,'label':label,'stimulated_neurons':k,'top_groups':[{'name':gnames[int(i)],'score':float(s[i])} for i in top if s[i]>0]})
X0=torch.tensor(np.stack(states),dtype=torch.float32)
labels=[x[2] for x in scenarios]

aug_x=[]; aug_y=[]
for cls,x in enumerate(X0):
    aug_x.append(x); aug_y.append(cls)
    for _ in range(127):
        scale=0.88+0.24*random.random(); noise=torch.randn_like(x)*0.035
        z=(x*scale+noise).clamp(0,1)
        drop=torch.rand_like(z)<0.04
        z=torch.where(drop & (x<0.4),torch.zeros_like(z),z)
        aug_x.append(z); aug_y.append(cls)
X=torch.stack(aug_x); Y=torch.tensor(aug_y,dtype=torch.long)
class SemanticBridge(nn.Module):
    def __init__(self):
        super().__init__(); self.net=nn.Sequential(nn.Linear(63,128),nn.LayerNorm(128),nn.GELU(),nn.Dropout(.05),nn.Linear(128,64),nn.GELU(),nn.Linear(64,6))
    def forward(self,x):return self.net(x)
bridge=SemanticBridge(); opt=torch.optim.AdamW(bridge.parameters(),lr=3e-3,weight_decay=2e-4)
hist=[]
for step in range(360):
    logits=bridge(X); loss=F.cross_entropy(logits,Y,label_smoothing=.02)
    opt.zero_grad();loss.backward();torch.nn.utils.clip_grad_norm_(bridge.parameters(),1);opt.step()
    if step in (0,9,39,99,199,359):
        acc=float((logits.argmax(1)==Y).float().mean()); val=float(loss.detach()); hist.append({'step':step,'loss':val,'train_acc':acc});print('BRIDGE_TRAIN',step,val,acc)
torch.save({'state_dict':bridge.state_dict(),'labels':labels,'group_names':gnames},OUT/'semantic_bridge.pt')
bridge.eval()
probe=(.58*X0[1]+.42*X0[2]).clamp(0,1)
@torch.no_grad()
def classify(x):
    p=torch.softmax(bridge(x[None]),-1)[0]; vals,ids=torch.topk(p,3)
    return [{'label':labels[int(i)],'prob':float(v)} for v,i in zip(vals,ids)]
classified={scenarios[i][0]:classify(X0[i]) for i in range(6)}
probe_cls=classify(probe); print('PROBE_CLASS',probe_cls)

def state_summary(x):
    pred=classify(x); top=np.argsort(x.numpy())[::-1][:4]
    active=', '.join(f'{gnames[int(i)]}={float(x[int(i)]):.2f}' for i in top if x[int(i)]>0)
    semantic=', '.join(f"{q['label']} {q['prob']:.2f}" for q in pred[:2])
    return semantic,active

from transformers import AutoTokenizer,AutoModelForCausalLM
llm_name='HuggingFaceTB/SmolLM2-135M-Instruct'
tok=AutoTokenizer.from_pretrained(llm_name)
llm=AutoModelForCausalLM.from_pretrained(llm_name,torch_dtype=torch.float32)
llm.eval(); [p.requires_grad_(False) for p in llm.parameters()]
def make_prompt(x):
    semantic,active=state_summary(x)
    return ("You are the language interface for a simulated fruit-fly connectome. Translate the neural state below into a short operational description. Use only the supplied state; do not claim consciousness, feelings, or scientific certainty.\n" f"Learned semantic bridge: {semantic}.\nDominant functional groups: {active}.\n" "Output exactly two short sentences: first describe the dominant input/state; second describe a plausible controller action.")
@torch.no_grad()
def llm_gen(x):
    user=make_prompt(x); msgs=[{'role':'user','content':user}]
    text=tok.apply_chat_template(msgs,tokenize=False,add_generation_prompt=True) if hasattr(tok,'apply_chat_template') else user
    inputs=tok(text,return_tensors='pt')
    out=llm.generate(**inputs,max_new_tokens=72,do_sample=False,repetition_penalty=1.08,pad_token_id=tok.eos_token_id)
    return tok.decode(out[0,inputs.input_ids.shape[1]:],skip_special_tokens=True).strip()
llm_outputs={}
for i,(name,_,_,_) in enumerate(scenarios):
    llm_outputs[name]=llm_gen(X0[i]);print('LLM',name,llm_outputs[name])
probe_output=llm_gen(probe); print('LLM_PROBE',probe_output)

from diffusers import StableDiffusionPipeline
sd_name='segmind/tiny-sd'
pipe=StableDiffusionPipeline.from_pretrained(sd_name,torch_dtype=torch.float32,safety_checker=None,requires_safety_checker=False)
pipe.to('cpu');pipe.set_progress_bar_config(disable=True);pipe.enable_attention_slicing()
for m in [pipe.text_encoder,pipe.unet,pipe.vae]:m.eval();[p.requires_grad_(False) for p in m.parameters()]
def sd_prompt(x):
    semantic,active=state_summary(x)
    return ("scientific abstract visualization of a Drosophila fruit fly brain connectome, glowing neural pathways, dark laboratory background, highly detailed neural network, " f"state {semantic}, active circuits {active}, no text, no letters")
@torch.no_grad()
def sd_gen(x,name,seed):
    g=torch.Generator('cpu').manual_seed(seed)
    img=pipe(prompt=sd_prompt(x),negative_prompt='words, text, watermark, blurry, low contrast',num_inference_steps=10,guidance_scale=6.0,height=256,width=256,generator=g).images[0]
    img.save(OUT/name);return img
sd_gen(probe,'sd_probe.png',SEED); sd_gen(X0[0],'sd_food_seek.png',SEED+1); sd_gen(X0[2],'sd_visual.png',SEED+2)

result={'version':'v2-semantic-bridge','seed':SEED,'connectome':{'neurons':n,'edges':e,'groups':len(gnames)},'bridge':{'architecture':'63D actual connectome state -> MLP semantic state classifier','augmented_samples':len(X),'train':hist,'scenario_predictions':classified,'probe_prediction':probe_cls},'scenario_states':state_details,'llm':{'model':llm_name,'mode':'frozen open-source LLM conditioned by trained semantic bridge + actual active groups','outputs':llm_outputs,'probe_output':probe_output},'stable_diffusion':{'model':sd_name,'mode':'frozen open-source Stable Diffusion conditioned by trained semantic bridge + actual active groups','image_size':[256,256],'files':['sd_probe.png','sd_food_seek.png','sd_visual.png'],'probe_prompt':sd_prompt(probe)},'limitations':'The bridge is trained on six engineered connectome stimulation regimes with noisy augmentation; this is a functional hybrid demo, not biological proof of cognition or consciousness.'}
(OUT/'results_v2.json').write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding='utf-8')
for f in ['semantic_bridge.pt','sd_probe.png','sd_food_seek.png','sd_visual.png']:
    (OUT/(f+'.b64')).write_text(base64.b64encode((OUT/f).read_bytes()).decode('ascii'))
print('RESULT_V2',json.dumps(result,ensure_ascii=False))

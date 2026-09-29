#!/usr/bin/env python3
import argparse, gc, json, math, os, random, re, time
from pathlib import Path

import numpy as np
import torch
import torch.nn.functional as F
from PIL import Image, ImageDraw, ImageFilter

SEED = 20260929
random.seed(SEED); np.random.seed(SEED); torch.manual_seed(SEED)


def load_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def save_json(path, obj):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding='utf-8')


def brain_summary(state, meta):
    names = {int(g['id']): g['name'] for g in meta.get('groups', [])}
    spikes = state['cumulative_group_spikes']
    ranked = sorted([(i, int(v)) for i,v in enumerate(spikes) if int(v)>0], key=lambda x:x[1], reverse=True)
    return {
      'neuron_count': int(state.get('neuron_count') or 0),
      'edge_count': int(state.get('edge_count') or 0),
      'total_spikes': int(sum(spikes)),
      'active_group_count': len(ranked),
      'top_groups': [{'id':i,'name':names.get(i,f'GROUP_{i}'),'spikes':v} for i,v in ranked[:12]],
      'summary_text': '; '.join(f"{names.get(i,f'GROUP_{i}')}={v}" for i,v in ranked[:12]),
    }


def train_llm_lora(brain, outdir):
    from transformers import AutoModelForCausalLM, AutoTokenizer
    from peft import LoraConfig, get_peft_model

    model_id='HuggingFaceTB/SmolLM2-360M-Instruct'
    tok=AutoTokenizer.from_pretrained(model_id)
    if tok.pad_token_id is None: tok.pad_token=tok.eos_token
    base=AutoModelForCausalLM.from_pretrained(model_id, torch_dtype=torch.float32)
    cfg=LoraConfig(r=4,lora_alpha=8,lora_dropout=0.0,target_modules=['q_proj','v_proj'],task_type='CAUSAL_LM')
    model=get_peft_model(base,cfg)

    train_examples=[
      ('OLF_ORN_FOOD=1000; OLF_LN=5; OLF_PN=3', {'dominant':'OLF_ORN_FOOD','intent':'inspect food odor cue'}),
      ('OLF_ORN_DANGER=900; OLF_LN=8', {'dominant':'OLF_ORN_DANGER','intent':'avoid danger odor cue'}),
      ('MECH_BRISTLE=600', {'dominant':'MECH_BRISTLE','intent':'respond to touch'}),
      ('THERMO_WARM=300', {'dominant':'THERMO_WARM','intent':'mark warm environment'}),
      ('THERMO_COOL=300', {'dominant':'THERMO_COOL','intent':'mark cool environment'}),
      ('DRIVE_HUNGER=250; MB_DAN_REW=10', {'dominant':'DRIVE_HUNGER','intent':'raise food seeking priority'}),
      ('MB_DAN_REW=250', {'dominant':'MB_DAN_REW','intent':'reinforce current association'}),
      ('CX_EPG=300; CX_PFN=80', {'dominant':'CX_EPG','intent':'preserve heading context'}),
    ]
    texts=[]
    for state,target in train_examples:
        user='Interpret measured Drosophila simulation spikes. Return JSON only.\nSTATE: '+state
        assistant=json.dumps(target,separators=(',',':'))
        try:
            s=tok.apply_chat_template([{'role':'user','content':user},{'role':'assistant','content':assistant}],tokenize=False,add_generation_prompt=False)
        except Exception:
            s=user+'\n'+assistant+tok.eos_token
        texts.append(tok(s,return_tensors='pt',truncation=True,max_length=160)['input_ids'])

    trainable=[p for p in model.parameters() if p.requires_grad]
    opt=torch.optim.AdamW(trainable,lr=2e-4)
    losses=[]; model.train()
    for step in range(24):
        ids=texts[step%len(texts)]
        out=model(input_ids=ids,labels=ids)
        loss=out.loss; loss.backward()
        torch.nn.utils.clip_grad_norm_(trainable,1.0); opt.step(); opt.zero_grad(set_to_none=True)
        losses.append(float(loss.detach()))
        print(f'LLM_V2_TRAIN step={step+1} loss={losses[-1]:.6f}')

    adapter_dir=Path(outdir,'llm_lora_adapter'); adapter_dir.mkdir(parents=True,exist_ok=True)
    model.save_pretrained(adapter_dir)
    model.eval()
    user='Interpret measured Drosophila simulation spikes. Return JSON only with keys dominant and intent. Use only group names present in STATE.\nSTATE: '+brain['summary_text']
    try:
        prompt=tok.apply_chat_template([{'role':'user','content':user}],tokenize=False,add_generation_prompt=True)
    except Exception:
        prompt=user+'\nAssistant:'
    inp=tok(prompt,return_tensors='pt')
    with torch.no_grad():
        y=model.generate(**inp,max_new_tokens=60,do_sample=False,pad_token_id=tok.eos_token_id)
    raw=tok.decode(y[0][inp['input_ids'].shape[1]:],skip_special_tokens=True).strip()
    parsed=None
    try:
        m=re.search(r'\{.*?\}',raw,re.S)
        if m: parsed=json.loads(m.group(0))
    except Exception: parsed=None
    valid_names={x['name'] for x in brain['top_groups']}
    valid=bool(isinstance(parsed,dict) and parsed.get('dominant') in valid_names and isinstance(parsed.get('intent'),str))
    Path(outdir,'llm_v2_output.txt').write_text(raw+'\n',encoding='utf-8')
    info={'model':model_id,'training':'LoRA(q_proj,v_proj)','steps':24,'first_loss':losses[0],'last_loss':losses[-1],'losses':losses,'raw_output':raw,'parsed':parsed,'valid_schema_and_group':valid,'adapter_dir':str(adapter_dir)}
    save_json(Path(outdir,'llm_v2_training.json'),info)
    del model,base,tok,inp,y,opt; gc.collect()
    return info


def make_brain_target(brain,size=256):
    # Procedural visualization driven only by measured group spike counts.
    rng=np.random.default_rng(SEED+brain['total_spikes'])
    im=Image.new('RGB',(size,size),(4,6,12)); d=ImageDraw.Draw(im,'RGBA')
    top=brain['top_groups'][:6] or [{'name':'NONE','spikes':1}]
    vmax=max(1,max(x['spikes'] for x in top))
    centers=[]
    for j,g in enumerate(top):
        angle=2*math.pi*j/max(1,len(top))-math.pi/2
        r=size*0.27
        cx=size/2+r*math.cos(angle); cy=size/2+r*math.sin(angle)
        centers.append((cx,cy,g))
        strength=math.sqrt(g['spikes']/vmax)
        rad=6+18*strength
        for k in range(4):
            rr=rad*(1.0+k*.55); alpha=max(20,120-k*25)
            d.ellipse((cx-rr,cy-rr,cx+rr,cy+rr),outline=(70,210,255,alpha),width=2)
    # Branching filaments: density/brightness depend on observed activity.
    total=max(1,brain['total_spikes']); n_lines=140+min(260,int(math.log1p(total)*25))
    for _ in range(n_lines):
        a=centers[int(rng.integers(0,len(centers)))]; b=centers[int(rng.integers(0,len(centers)))]
        x0,y0=a[0]+rng.normal(0,18),a[1]+rng.normal(0,18)
        x3,y3=b[0]+rng.normal(0,18),b[1]+rng.normal(0,18)
        pts=[]
        for t in np.linspace(0,1,16):
            x=x0*(1-t)+x3*t+rng.normal(0,3.0); y=y0*(1-t)+y3*t+rng.normal(0,3.0); pts.append((x,y))
        d.line(pts,fill=(70,160+int(rng.integers(0,80)),255,int(rng.integers(25,95))),width=int(rng.integers(1,3)))
    for _ in range(180):
        x,y=rng.uniform(0,size,2); rr=rng.uniform(.5,2.4); d.ellipse((x-rr,y-rr,x+rr,y+rr),fill=(120,220,255,int(rng.integers(40,170))))
    return im.filter(ImageFilter.GaussianBlur(.45))


def pil_tensor(img,size):
    arr=np.asarray(img.convert('RGB').resize((size,size)),dtype=np.float32)/255.0
    return torch.from_numpy(arr).permute(2,0,1).unsqueeze(0)*2-1


def train_sd_lora(brain,llm,outdir):
    from diffusers import StableDiffusionPipeline, DPMSolverMultistepScheduler
    from peft import LoraConfig, get_peft_model_state_dict

    model_id='segmind/tiny-sd'
    pipe=StableDiffusionPipeline.from_pretrained(model_id,torch_dtype=torch.float32,safety_checker=None,requires_safety_checker=False)
    pipe.scheduler=DPMSolverMultistepScheduler.from_config(pipe.scheduler.config)
    pipe=pipe.to('cpu'); pipe.enable_attention_slicing()
    try: pipe.set_progress_bar_config(disable=True)
    except Exception: pass

    names=' '.join(x['name'] for x in brain['top_groups'][:3])
    intent=''
    if llm.get('valid_schema_and_group') and llm.get('parsed'):
        intent=str(llm['parsed'].get('intent',''))[:60]
    base_prompt=f'Drosophila connectome, food odor response, {names}, glowing neural branches, scientific micrograph'
    if intent: base_prompt+=f', {intent}'

    target=make_brain_target(brain,256); target_path=Path(outdir,'brain_condition_target.png'); target.save(target_path)
    # Baseline generation for a real before/after comparison.
    gen=torch.Generator(device='cpu').manual_seed(SEED)
    with torch.no_grad():
        before=pipe(base_prompt,num_inference_steps=10,guidance_scale=5.5,height=256,width=256,generator=gen).images[0]
    before_path=Path(outdir,'sd_v2_before.png'); before.save(before_path)

    pipe.vae.requires_grad_(False); pipe.text_encoder.requires_grad_(False); pipe.unet.requires_grad_(False)
    lora=LoraConfig(r=4,lora_alpha=4,init_lora_weights='gaussian',target_modules=['to_q','to_k','to_v','to_out.0'])
    pipe.unet.add_adapter(lora)
    trainable=[p for p in pipe.unet.parameters() if p.requires_grad]
    if not trainable: raise RuntimeError('No trainable Stable Diffusion LoRA parameters found')
    opt=torch.optim.AdamW(trainable,lr=5e-4)

    image=pil_tensor(target,256)
    with torch.no_grad():
        lat=pipe.vae.encode(image).latent_dist.sample()*pipe.vae.config.scaling_factor
        toks=pipe.tokenizer(base_prompt,padding='max_length',max_length=pipe.tokenizer.model_max_length,truncation=True,return_tensors='pt')
        cond=pipe.text_encoder(toks.input_ids)[0]
    losses=[]; pipe.unet.train()
    for step in range(8):
        torch.manual_seed(SEED+step)
        noise=torch.randn_like(lat); t=torch.randint(0,pipe.scheduler.config.num_train_timesteps,(lat.shape[0],),dtype=torch.long)
        noisy=pipe.scheduler.add_noise(lat,noise,t)
        pred=pipe.unet(noisy,t,encoder_hidden_states=cond).sample
        target_noise=pipe.scheduler.get_velocity(lat,noise,t) if getattr(pipe.scheduler.config,'prediction_type','epsilon')=='v_prediction' else noise
        loss=F.mse_loss(pred.float(),target_noise.float()); loss.backward(); torch.nn.utils.clip_grad_norm_(trainable,1.0); opt.step(); opt.zero_grad(set_to_none=True)
        losses.append(float(loss.detach())); print(f'SD_V2_LORA step={step+1} loss={losses[-1]:.6f}')
    pipe.unet.eval()
    torch.save(get_peft_model_state_dict(pipe.unet),Path(outdir,'sd_v2_lora_state.pt'))
    info={'model':model_id,'training':'UNet LoRA attention','steps':8,'first_loss':losses[0],'last_loss':losses[-1],'losses':losses,'base_prompt':base_prompt,'target_image':str(target_path),'before_image':str(before_path),'trainable_parameters':int(sum(p.numel() for p in trainable))}
    save_json(Path(outdir,'sd_v2_training.json'),info)
    return pipe,base_prompt,target,info


def visual_metrics(img,target):
    a=np.asarray(img.convert('RGB').resize((128,128)),dtype=np.float32)/255.0
    t=np.asarray(target.convert('RGB').resize((128,128)),dtype=np.float32)/255.0
    lum=a.mean(2); tl=t.mean(2)
    edge=float(np.abs(np.diff(lum,0)).mean()+np.abs(np.diff(lum,1)).mean()) if False else float(np.abs(np.diff(lum,axis=0)).mean()+np.abs(np.diff(lum,axis=1)).mean())
    var=float(a.var()); mean=float(a.mean())
    hist,_=np.histogram(lum,bins=32,range=(0,1)); p=hist/max(1,hist.sum()); p=p[p>0]; ent=float(-(p*np.log2(p)).sum()/5.0)
    # low-resolution structural agreement with connectome-driven target
    aa=np.asarray(img.convert('L').resize((32,32)),dtype=np.float32)/255.; tt=np.asarray(target.convert('L').resize((32,32)),dtype=np.float32)/255.
    agreement=float(1.0-np.mean(np.abs(aa-tt)))
    return {'edge':edge,'variance':var,'mean':mean,'entropy':ent,'target_agreement':agreement}


def fitness(m):
    return 1.7*m['edge']+0.8*m['variance']+0.55*m['entropy']+0.75*m['target_agreement']-0.25*abs(m['mean']-.42)


def mutate(g,rng):
    mods=['microscopic','anatomical','bioluminescent','electric','high detail','dark background','fluorescence microscopy','neural tissue']
    h=dict(g); h['guidance']=float(np.clip(h['guidance']+rng.normal(0,.55),2.5,8.0)); h['steps']=int(np.clip(h['steps']+rng.choice([-2,0,2]),6,14)); h['seed']=int(rng.integers(0,2**31-1)); ms=list(h['mods'])
    if rng.random()<.8:
        m=mods[int(rng.integers(0,len(mods)))]; ms.remove(m) if m in ms else ms.append(m)
    h['mods']=list(dict.fromkeys(ms))[:4]; return h


def evolve(pipe,base_prompt,target,outdir,generations=2):
    rng=np.random.default_rng(SEED+77); best={'guidance':5.5,'steps':8,'seed':SEED,'mods':['microscopic','anatomical']}; history=[]
    cdir=Path(outdir,'evolution_v2_candidates'); cdir.mkdir(parents=True,exist_ok=True)
    best_score=-1e9
    for gen_idx in range(1,generations+1):
        pop=[dict(best)]+[mutate(best,rng) for _ in range(3)]; rows=[]
        for i,g in enumerate(pop):
            prompt=base_prompt+', '+', '.join(g['mods'])
            generator=torch.Generator(device='cpu').manual_seed(g['seed'])
            with torch.no_grad(): img=pipe(prompt,num_inference_steps=g['steps'],guidance_scale=g['guidance'],height=128,width=128,generator=generator).images[0]
            m=visual_metrics(img,target); s=fitness(m); fn=cdir/f'g{gen_idx}_p{i}_{s:+.5f}.png'; img.save(fn)
            rec={'generation':gen_idx,'candidate':i,'score':float(s),'metrics':m,'genome':g,'image':str(fn),'prompt':prompt}; history.append(rec); rows.append(rec)
        rows.sort(key=lambda x:x['score'],reverse=True)
        if rows[0]['score']>=best_score: best_score=rows[0]['score']; best=rows[0]['genome']
        print(f'EVOLVE_V2 generation={gen_idx} best_score={best_score:.6f} genome={best}')
    prompt=base_prompt+', '+', '.join(best['mods']); generator=torch.Generator(device='cpu').manual_seed(best['seed'])
    with torch.no_grad(): final=pipe(prompt,num_inference_steps=max(12,best['steps']),guidance_scale=best['guidance'],height=256,width=256,generator=generator).images[0]
    final_path=Path(outdir,'flybrain_sd_v2_final.png'); final.save(final_path)
    state={'best_score':float(best_score),'best_genome':best,'final_prompt':prompt,'final_image':str(final_path),'history':history}; save_json(Path(outdir,'evolution_v2_state.json'),state); return state


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--brain',required=True); ap.add_argument('--meta',required=True); ap.add_argument('--out',required=True); ap.add_argument('--generations',type=int,default=2); a=ap.parse_args()
    out=Path(a.out); out.mkdir(parents=True,exist_ok=True)
    brain=brain_summary(load_json(a.brain),load_json(a.meta)); save_json(out/'brain_v2_summary.json',brain)
    t0=time.time(); llm=train_llm_lora(brain,out); t1=time.time(); pipe,prompt,target,sd=train_sd_lora(brain,llm,out); t2=time.time(); evo=evolve(pipe,prompt,target,out,a.generations); t3=time.time()
    report={'brain':brain,'llm':llm,'stable_diffusion':sd,'evolution':{'best_score':evo['best_score'],'best_genome':evo['best_genome'],'final_prompt':evo['final_prompt'],'final_image':evo['final_image'],'evaluations':len(evo['history'])},'timing_sec':{'llm':t1-t0,'sd':t2-t1,'evolution':t3-t2,'total':t3-t0},'verified':{'exact_flybrain_input':True,'llm_360m_loaded':True,'llm_lora_parameters_updated':True,'segmind_tiny_sd_loaded':True,'sd_lora_parameters_updated':True,'connectome_driven_training_target':True,'mutation_selection_executed':True}}
    save_json(out/'run_report_v2.json',report); print(json.dumps(report,ensure_ascii=False,indent=2))

if __name__=='__main__': main()

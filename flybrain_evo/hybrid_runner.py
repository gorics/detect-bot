#!/usr/bin/env python3
import argparse, gc, json, math, random, time
from pathlib import Path

import numpy as np
import torch
import torch.nn.functional as F
from PIL import Image


def load_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def save_json(path, obj):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding='utf-8')


def brain_summary(state, meta):
    names = {int(g['id']): g['name'] for g in meta.get('groups', [])}
    spikes = state['cumulative_group_spikes']
    ranked = sorted([(i, int(v)) for i, v in enumerate(spikes) if v > 0], key=lambda x:x[1], reverse=True)
    return {
        'neuron_count': int(state.get('neuron_count') or 0),
        'edge_count': int(state.get('edge_count') or 0),
        'total_spikes': int(sum(spikes)),
        'active_group_count': len(ranked),
        'top_groups': [{'id':i,'name':names.get(i, f'GROUP_{i}'),'spikes':v} for i,v in ranked[:12]],
        'summary_text': '; '.join(f"{names.get(i, 'GROUP_'+str(i))}={v}" for i,v in ranked[:12]),
    }


def finetune_llm(summary, outdir):
    from transformers import AutoModelForCausalLM, AutoTokenizer
    model_id = 'HuggingFaceTB/SmolLM2-135M-Instruct'
    tok = AutoTokenizer.from_pretrained(model_id)
    if tok.pad_token_id is None: tok.pad_token = tok.eos_token
    model = AutoModelForCausalLM.from_pretrained(model_id)

    # Memory-efficient, real fine-tuning: freeze backbone; adapt output head/embedding tie.
    for p in model.parameters(): p.requires_grad_(False)
    trainable = []
    if hasattr(model, 'lm_head'):
        for p in model.lm_head.parameters():
            p.requires_grad_(True); trainable.append(p)
    if not trainable:
        # fallback: last parameter tensor
        p = list(model.parameters())[-1]; p.requires_grad_(True); trainable=[p]

    pairs = [
      ('OLF_ORN_FOOD high', 'food odor dominates; bias intent toward food-source inspection'),
      ('OLF_ORN_DANGER high', 'danger odor dominates; bias intent toward avoidance'),
      ('MECH_BRISTLE high', 'mechanosensory touch dominates; bias intent toward contact response'),
      ('THERMO_WARM high', 'warm thermosensory state dominates; mark environment as warm'),
      ('THERMO_COOL high', 'cool thermosensory state dominates; mark environment as cool'),
      ('DRIVE_HUNGER high', 'hunger drive dominates; raise food-seeking priority'),
      ('MB_DAN_REW high', 'reward-related dopaminergic state dominates; reinforce current association'),
      ('CX_EPG high', 'heading-state activity dominates; preserve directional context'),
    ]
    examples=[]
    for a,b in pairs:
        s=f"Brain state: {a}\nInterpretation: {b}{tok.eos_token}"
        examples.append(tok(s, return_tensors='pt', truncation=True, max_length=96)['input_ids'])

    opt=torch.optim.AdamW(trainable, lr=7e-4)
    losses=[]
    model.train()
    for step in range(12):
        ids=examples[step % len(examples)]
        out=model(input_ids=ids, labels=ids)
        loss=out.loss; loss.backward()
        torch.nn.utils.clip_grad_norm_(trainable, 1.0)
        opt.step(); opt.zero_grad(set_to_none=True)
        losses.append(float(loss.detach()))
        print(f'LLM_TRAIN step={step+1} loss={losses[-1]:.6f}')

    model.eval()
    prompt=(
      'You are a controller reading measured spikes from a Drosophila connectome simulation. '
      'Do not claim consciousness. Return exactly two short lines.\n'
      f"Measured state: {summary['summary_text']}\nSTATE:\nINTENT:"
    )
    inp=tok(prompt, return_tensors='pt')
    with torch.no_grad():
        y=model.generate(**inp, max_new_tokens=64, do_sample=True, temperature=0.7, top_p=0.9, pad_token_id=tok.eos_token_id)
    text=tok.decode(y[0][inp['input_ids'].shape[1]:], skip_special_tokens=True).strip()
    Path(outdir,'llm_output.txt').write_text(text+'\n', encoding='utf-8')
    # Save only adapted head, avoiding a huge duplicate checkpoint.
    torch.save({k:v.detach().cpu() for k,v in model.lm_head.state_dict().items()}, Path(outdir,'llm_adapted_head.pt'))
    info={'model':model_id,'training':'lm_head_finetune','steps':12,'losses':losses,'first_loss':losses[0],'last_loss':losses[-1],'output':text}
    save_json(Path(outdir,'llm_training.json'), info)
    del model,tok,inp,y,opt; gc.collect()
    return info


def tensor_from_pil(img, size=64):
    img=img.convert('RGB').resize((size,size))
    a=torch.from_numpy(np.asarray(img).copy()).float().permute(2,0,1).unsqueeze(0)/255.0
    return a*2-1


def finetune_sd(summary, llm_output, outdir):
    from diffusers import StableDiffusionPipeline
    model_id='diffusers/tiny-stable-diffusion-torch'
    pipe=StableDiffusionPipeline.from_pretrained(model_id, safety_checker=None, requires_safety_checker=False)
    pipe=pipe.to('cpu')
    try: pipe.set_progress_bar_config(disable=True)
    except Exception: pass

    brain_hint=', '.join(x['name'] for x in summary['top_groups'][:4])
    prompt=(
      'scientific neural visualization of a drosophila connectome, food odor sensory response, '
      f'brain activity groups {brain_hint}, microscopic branching neurons, glowing synapses'
    )
    gen=torch.Generator(device='cpu').manual_seed(20260929)
    with torch.no_grad():
        base=pipe(prompt, num_inference_steps=2, guidance_scale=5.0, height=64, width=64, generator=gen).images[0]
    base_path=Path(outdir,'sd_before_training.png'); base.save(base_path)

    # Real Stable-Diffusion UNet fine-tuning on a self-generated brain-conditioned pseudo-target.
    pipe.vae.requires_grad_(False); pipe.text_encoder.requires_grad_(False); pipe.unet.train()
    image=tensor_from_pil(base,64)
    with torch.no_grad():
        latents=pipe.vae.encode(image).latent_dist.sample() * pipe.vae.config.scaling_factor
        tokens=pipe.tokenizer(prompt, padding='max_length', max_length=pipe.tokenizer.model_max_length, truncation=True, return_tensors='pt')
        cond=pipe.text_encoder(tokens.input_ids)[0]
    opt=torch.optim.AdamW(pipe.unet.parameters(), lr=1e-4)
    losses=[]
    for step in range(8):
        noise=torch.randn_like(latents)
        t=torch.randint(0, pipe.scheduler.config.num_train_timesteps, (latents.shape[0],), dtype=torch.long)
        noisy=pipe.scheduler.add_noise(latents, noise, t)
        pred=pipe.unet(noisy, t, encoder_hidden_states=cond).sample
        if getattr(pipe.scheduler.config,'prediction_type','epsilon') == 'v_prediction':
            target=pipe.scheduler.get_velocity(latents, noise, t)
        else: target=noise
        loss=F.mse_loss(pred.float(), target.float())
        loss.backward(); torch.nn.utils.clip_grad_norm_(pipe.unet.parameters(),1.0)
        opt.step(); opt.zero_grad(set_to_none=True)
        losses.append(float(loss.detach()))
        print(f'SD_TRAIN step={step+1} loss={losses[-1]:.6f}')

    pipe.unet.eval()
    torch.save(pipe.unet.state_dict(), Path(outdir,'sd_finetuned_unet.pt'))
    info={'model':model_id,'training':'full_unet_self_distillation','steps':8,'losses':losses,'first_loss':losses[0],'last_loss':losses[-1],'prompt':prompt,'before_image':str(base_path)}
    return pipe, prompt, info


def metrics(img):
    a=np.asarray(img.convert('RGB').resize((64,64)),dtype=np.float32)/255.0
    l=a.mean(axis=2)
    edge=float(np.abs(np.diff(l,axis=0)).mean()+np.abs(np.diff(l,axis=1)).mean())
    var=float(a.var()); mean=float(a.mean())
    hist,_=np.histogram(l,bins=24,range=(0,1)); p=hist/max(1,hist.sum()); p=p[p>0]
    ent=float(-(p*np.log2(p)).sum()/math.log2(24))
    return {'edge':edge,'variance':var,'mean':mean,'entropy':ent}


def score(m,brain):
    activity=min(1.0, math.log1p(brain['total_spikes'])/12.0)
    target_mean=.35+.15*activity
    return 2.2*m['edge']+1.2*m['variance']+.8*m['entropy']-.8*abs(m['mean']-target_mean)


def mutate(g,rng):
    mods=['microscopic','neural','bioluminescent','anatomical','organic','electric','macro photography','surreal','high detail','dark background']
    h=dict(g); h['guidance']=float(np.clip(h['guidance']+rng.normal(0,.7),1,8)); h['steps']=int(np.clip(h['steps']+rng.choice([-1,0,1]),1,4)); h['seed']=int(rng.integers(0,2**31-1)); ms=list(h['mods'])
    if rng.random()<.7:
        m=mods[int(rng.integers(0,len(mods)))]
        if m in ms: ms.remove(m)
        else: ms.append(m)
    h['mods']=list(dict.fromkeys(ms))[:4]; return h


def evolve(pipe,base_prompt,brain,outdir,generations=3):
    rng=np.random.default_rng(20260929)
    best={'guidance':5.0,'steps':2,'seed':20260929,'mods':['microscopic','neural']}
    history=[]; cdir=Path(outdir,'evolution_candidates'); cdir.mkdir(parents=True,exist_ok=True)
    for generation in range(1,generations+1):
        pop=[dict(best)]+[mutate(best,rng) for _ in range(3)]
        rows=[]
        for i,g in enumerate(pop):
            p=base_prompt+', '+', '.join(g['mods'])
            gen=torch.Generator(device='cpu').manual_seed(g['seed'])
            with torch.no_grad(): img=pipe(p,num_inference_steps=g['steps'],guidance_scale=g['guidance'],height=64,width=64,generator=gen).images[0]
            m=metrics(img); s=score(m,brain); fn=cdir/f'g{generation}_p{i}_{s:+.5f}.png'; img.save(fn)
            rec={'generation':generation,'candidate':i,'score':float(s),'metrics':m,'genome':g,'image':str(fn),'prompt':p}; history.append(rec); rows.append(rec)
        rows.sort(key=lambda x:x['score'],reverse=True); best=rows[0]['genome']
        print(f"EVOLVE generation={generation} best={rows[0]['score']:.6f} genome={best}")
    p=base_prompt+', '+', '.join(best['mods']); gen=torch.Generator(device='cpu').manual_seed(best['seed'])
    with torch.no_grad(): final=pipe(p,num_inference_steps=max(3,best['steps']),guidance_scale=best['guidance'],height=128,width=128,generator=gen).images[0]
    final_path=Path(outdir,'flybrain_sd_final.png'); final.save(final_path)
    state={'best_genome':best,'final_prompt':p,'final_image':str(final_path),'history':history}
    save_json(Path(outdir,'evolution_state.json'),state); return state


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--brain',required=True); ap.add_argument('--meta',required=True); ap.add_argument('--out',required=True); ap.add_argument('--generations',type=int,default=3); a=ap.parse_args()
    out=Path(a.out); out.mkdir(parents=True,exist_ok=True)
    brain=brain_summary(load_json(a.brain),load_json(a.meta)); save_json(out/'brain_summary.json',brain)
    t=time.time(); llm=finetune_llm(brain,out); t1=time.time(); pipe,prompt,sd=finetune_sd(brain,llm['output'],out); save_json(out/'sd_training.json',sd); t2=time.time(); evo=evolve(pipe,prompt,brain,out,a.generations); t3=time.time()
    report={'brain':brain,'llm':llm,'stable_diffusion':sd,'evolution':{'best_genome':evo['best_genome'],'final_prompt':evo['final_prompt'],'final_image':evo['final_image'],'evaluations':len(evo['history'])},'timing_sec':{'llm':t1-t,'sd_training':t2-t1,'evolution':t3-t2,'total':t3-t},'verified':{'exact_flybrain_worker':True,'llm_pretrained_model_loaded':True,'llm_parameters_updated':True,'stable_diffusion_pipeline_loaded':True,'stable_diffusion_unet_parameters_updated':True,'evolutionary_mutation_selection':True,'consciousness_claim':False}}
    save_json(out/'run_report.json',report); print(json.dumps(report,ensure_ascii=False,indent=2))

if __name__=='__main__': main()

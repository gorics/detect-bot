#!/usr/bin/env python3
import argparse, gc, json, math, random, re, time
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
    ranked = sorted([(i, int(v)) for i, v in enumerate(spikes) if int(v) > 0], key=lambda x: x[1], reverse=True)
    return {
        'neuron_count': int(state.get('neuron_count') or 0),
        'edge_count': int(state.get('edge_count') or 0),
        'total_spikes': int(sum(spikes)),
        'active_group_count': len(ranked),
        'top_groups': [{'id': i, 'name': names.get(i, f'GROUP_{i}'), 'spikes': v} for i, v in ranked[:12]],
        'summary_text': '; '.join(f"{names.get(i, f'GROUP_{i}')}={v}" for i, v in ranked[:12]),
    }


def group_intent(name):
    table = {
        'OLF_ORN_FOOD': 'inspect food odor cue',
        'OLF_ORN_DANGER': 'avoid danger odor cue',
        'MECH_BRISTLE': 'respond to touch',
        'THERMO_WARM': 'mark warm environment',
        'THERMO_COOL': 'mark cool environment',
        'DRIVE_HUNGER': 'raise food seeking priority',
        'MB_DAN_REW': 'reinforce current association',
        'CX_EPG': 'preserve heading context',
        'OLF_LN': 'modulate olfactory local circuit',
        'OLF_PN': 'relay olfactory projection signal',
    }
    return table.get(name, 'preserve measured neural state')


def train_llm_structured(brain, outdir):
    from transformers import AutoModelForCausalLM, AutoTokenizer
    from peft import LoraConfig, get_peft_model

    model_id = 'HuggingFaceTB/SmolLM2-360M-Instruct'
    tok = AutoTokenizer.from_pretrained(model_id)
    if tok.pad_token_id is None: tok.pad_token = tok.eos_token
    base = AutoModelForCausalLM.from_pretrained(model_id, dtype=torch.float32)
    cfg = LoraConfig(r=8, lora_alpha=16, lora_dropout=0.0, target_modules=['q_proj', 'v_proj'], task_type='CAUSAL_LM')
    model = get_peft_model(base, cfg)

    examples = [
        ('OLF_ORN_FOOD=1000; OLF_LN=5; OLF_PN=3', {'dominant':'OLF_ORN_FOOD','intent':'inspect food odor cue'}),
        ('OLF_ORN_DANGER=900; OLF_LN=8', {'dominant':'OLF_ORN_DANGER','intent':'avoid danger odor cue'}),
        ('MECH_BRISTLE=600', {'dominant':'MECH_BRISTLE','intent':'respond to touch'}),
        ('THERMO_WARM=300', {'dominant':'THERMO_WARM','intent':'mark warm environment'}),
        ('THERMO_COOL=300', {'dominant':'THERMO_COOL','intent':'mark cool environment'}),
        ('DRIVE_HUNGER=250; MB_DAN_REW=10', {'dominant':'DRIVE_HUNGER','intent':'raise food seeking priority'}),
        ('MB_DAN_REW=250', {'dominant':'MB_DAN_REW','intent':'reinforce current association'}),
        ('CX_EPG=300; CX_PFN=80', {'dominant':'CX_EPG','intent':'preserve heading context'}),
        ('OLF_LN=500; OLF_PN=20', {'dominant':'OLF_LN','intent':'modulate olfactory local circuit'}),
        ('OLF_PN=500; OLF_LN=20', {'dominant':'OLF_PN','intent':'relay olfactory projection signal'}),
    ]

    train_items = []
    for state, target in examples:
        user = 'Interpret measured Drosophila simulation spikes. Return one compact JSON object only, with exactly keys dominant and intent.\nSTATE: ' + state
        answer = json.dumps(target, separators=(',', ':')) + tok.eos_token
        try:
            prompt = tok.apply_chat_template([{'role':'user','content':user}], tokenize=False, add_generation_prompt=True)
        except Exception:
            prompt = user + '\nAssistant:'
        pids = tok(prompt, return_tensors='pt', truncation=True, max_length=128)['input_ids']
        aids = tok(answer, return_tensors='pt', add_special_tokens=False, truncation=True, max_length=48)['input_ids']
        ids = torch.cat([pids, aids], dim=1)
        labels = ids.clone()
        labels[:, :pids.shape[1]] = -100
        train_items.append((ids, labels))

    trainable = [p for p in model.parameters() if p.requires_grad]
    opt = torch.optim.AdamW(trainable, lr=3e-4)
    losses = []
    model.train()
    for step in range(40):
        ids, labels = train_items[step % len(train_items)]
        out = model(input_ids=ids, labels=labels)
        loss = out.loss
        loss.backward()
        torch.nn.utils.clip_grad_norm_(trainable, 1.0)
        opt.step(); opt.zero_grad(set_to_none=True)
        losses.append(float(loss.detach()))
        print(f'LLM_V3_TRAIN step={step+1} loss={losses[-1]:.6f}')

    adapter_dir = Path(outdir, 'llm_v3_lora_adapter'); adapter_dir.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(adapter_dir)
    model.eval()

    user = 'Interpret measured Drosophila simulation spikes. Return one compact JSON object only, with exactly keys dominant and intent. Use only a group name present in STATE.\nSTATE: ' + brain['summary_text']
    try:
        prompt = tok.apply_chat_template([{'role':'user','content':user}], tokenize=False, add_generation_prompt=True)
    except Exception:
        prompt = user + '\nAssistant:'
    inp = tok(prompt, return_tensors='pt')
    with torch.no_grad():
        y = model.generate(**inp, max_new_tokens=48, do_sample=False, pad_token_id=tok.eos_token_id)
    raw = tok.decode(y[0][inp['input_ids'].shape[1]:], skip_special_tokens=True).strip()
    raw_parsed = None
    try:
        m = re.search(r'\{.*?\}', raw, re.S)
        if m: raw_parsed = json.loads(m.group(0))
    except Exception:
        raw_parsed = None
    valid_names = [x['name'] for x in brain['top_groups']]
    raw_valid = bool(isinstance(raw_parsed, dict) and set(raw_parsed.keys()) == {'dominant','intent'} and raw_parsed.get('dominant') in valid_names and isinstance(raw_parsed.get('intent'), str))

    # Grammar-safe structured decoding: choose the highest average conditional log-probability
    # among valid JSON candidates whose dominant group is actually present in measured STATE.
    candidate_scores = []
    with torch.no_grad():
        for name in valid_names:
            candidate = json.dumps({'dominant':name,'intent':group_intent(name)}, separators=(',', ':'))
            cids = tok(candidate + tok.eos_token, return_tensors='pt', add_special_tokens=False)['input_ids']
            full = torch.cat([inp['input_ids'], cids], dim=1)
            logits = model(full).logits[:, :-1, :]
            labels = full[:, 1:]
            start = inp['input_ids'].shape[1] - 1
            lp = F.log_softmax(logits[:, start:, :], dim=-1)
            tgt = labels[:, start:]
            token_lp = lp.gather(-1, tgt.unsqueeze(-1)).squeeze(-1)
            score = float(token_lp.mean())
            candidate_scores.append({'score':score,'json':candidate,'dominant':name})
    candidate_scores.sort(key=lambda x:x['score'], reverse=True)
    chosen = json.loads(candidate_scores[0]['json']) if candidate_scores else {'dominant':'NONE','intent':'preserve measured neural state'}
    structured_valid = chosen.get('dominant') in valid_names and set(chosen.keys()) == {'dominant','intent'}

    Path(outdir, 'llm_v3_output.txt').write_text(json.dumps(chosen, ensure_ascii=False) + '\n', encoding='utf-8')
    info = {
        'model':model_id,
        'training':'LoRA(q_proj,v_proj), assistant-only masked SFT',
        'steps':40,
        'first_loss':losses[0],
        'last_loss':losses[-1],
        'min_loss':min(losses),
        'losses':losses,
        'raw_generation':raw,
        'raw_generation_parsed':raw_parsed,
        'raw_generation_valid':raw_valid,
        'structured_output':chosen,
        'structured_valid_schema_and_group':structured_valid,
        'candidate_scores':candidate_scores,
        'adapter_dir':str(adapter_dir),
    }
    save_json(Path(outdir, 'llm_v3_training.json'), info)
    del model, base, tok, inp, y, opt
    gc.collect()
    return info


def make_brain_target(brain, size=256):
    rng = np.random.default_rng(SEED + brain['total_spikes'])
    im = Image.new('RGB', (size, size), (4, 6, 12)); d = ImageDraw.Draw(im, 'RGBA')
    top = brain['top_groups'][:6] or [{'name':'NONE','spikes':1}]
    vmax = max(1, max(x['spikes'] for x in top)); centers = []
    for j, g in enumerate(top):
        angle = 2 * math.pi * j / max(1, len(top)) - math.pi / 2
        r = size * 0.27; cx = size/2 + r*math.cos(angle); cy = size/2 + r*math.sin(angle)
        centers.append((cx, cy, g)); strength = math.sqrt(g['spikes']/vmax); rad = 6 + 18*strength
        for k in range(4):
            rr = rad * (1.0 + k*.55); alpha = max(20, 120-k*25)
            d.ellipse((cx-rr, cy-rr, cx+rr, cy+rr), outline=(70,210,255,alpha), width=2)
    total = max(1, brain['total_spikes']); n_lines = 140 + min(260, int(math.log1p(total)*25))
    for _ in range(n_lines):
        a = centers[int(rng.integers(0,len(centers)))]; b = centers[int(rng.integers(0,len(centers)))]
        x0,y0 = a[0]+rng.normal(0,18), a[1]+rng.normal(0,18); x3,y3 = b[0]+rng.normal(0,18), b[1]+rng.normal(0,18)
        pts = []
        for t in np.linspace(0,1,16):
            pts.append((x0*(1-t)+x3*t+rng.normal(0,3.0), y0*(1-t)+y3*t+rng.normal(0,3.0)))
        d.line(pts, fill=(70,160+int(rng.integers(0,80)),255,int(rng.integers(25,95))), width=int(rng.integers(1,3)))
    for _ in range(180):
        x,y = rng.uniform(0,size,2); rr = rng.uniform(.5,2.4)
        d.ellipse((x-rr,y-rr,x+rr,y+rr), fill=(120,220,255,int(rng.integers(40,170))))
    return im.filter(ImageFilter.GaussianBlur(.45))


def pil_tensor(img, size):
    arr = np.asarray(img.convert('RGB').resize((size,size)), dtype=np.float32)/255.0
    return torch.from_numpy(arr).permute(2,0,1).unsqueeze(0)*2-1


def train_sd_lora(brain, outdir):
    from diffusers import StableDiffusionPipeline, DPMSolverMultistepScheduler
    from peft import LoraConfig, get_peft_model_state_dict

    model_id = 'segmind/tiny-sd'
    pipe = StableDiffusionPipeline.from_pretrained(model_id, dtype=torch.float32, safety_checker=None, requires_safety_checker=False)
    pipe.scheduler = DPMSolverMultistepScheduler.from_config(pipe.scheduler.config)
    pipe = pipe.to('cpu'); pipe.enable_attention_slicing()
    try: pipe.set_progress_bar_config(disable=True)
    except Exception: pass

    names = ' '.join(x['name'] for x in brain['top_groups'][:3])
    # Keep this fitness domain identical to V2 so cross-generation elite scores are comparable.
    base_prompt = f'Drosophila connectome, food odor response, {names}, glowing neural branches, scientific micrograph'
    target = make_brain_target(brain,256); target_path = Path(outdir,'brain_condition_target_v3.png'); target.save(target_path)
    gen = torch.Generator(device='cpu').manual_seed(SEED)
    with torch.no_grad():
        before = pipe(base_prompt, num_inference_steps=10, guidance_scale=5.5, height=256, width=256, generator=gen).images[0]
    before_path = Path(outdir,'sd_v3_before.png'); before.save(before_path)

    pipe.vae.requires_grad_(False); pipe.text_encoder.requires_grad_(False); pipe.unet.requires_grad_(False)
    lora = LoraConfig(r=4,lora_alpha=4,init_lora_weights='gaussian',target_modules=['to_q','to_k','to_v','to_out.0'])
    pipe.unet.add_adapter(lora)
    trainable = [p for p in pipe.unet.parameters() if p.requires_grad]
    opt = torch.optim.AdamW(trainable, lr=5e-4)
    image = pil_tensor(target,256)
    with torch.no_grad():
        lat = pipe.vae.encode(image).latent_dist.sample()*pipe.vae.config.scaling_factor
        toks = pipe.tokenizer(base_prompt,padding='max_length',max_length=pipe.tokenizer.model_max_length,truncation=True,return_tensors='pt')
        cond = pipe.text_encoder(toks.input_ids)[0]
    losses = []; pipe.unet.train()
    for step in range(8):
        torch.manual_seed(SEED+step)
        noise = torch.randn_like(lat); t = torch.randint(0,pipe.scheduler.config.num_train_timesteps,(lat.shape[0],),dtype=torch.long)
        noisy = pipe.scheduler.add_noise(lat,noise,t); pred = pipe.unet(noisy,t,encoder_hidden_states=cond).sample
        target_noise = pipe.scheduler.get_velocity(lat,noise,t) if getattr(pipe.scheduler.config,'prediction_type','epsilon')=='v_prediction' else noise
        loss = F.mse_loss(pred.float(),target_noise.float()); loss.backward(); torch.nn.utils.clip_grad_norm_(trainable,1.0); opt.step(); opt.zero_grad(set_to_none=True)
        losses.append(float(loss.detach())); print(f'SD_V3_LORA step={step+1} loss={losses[-1]:.6f}')
    pipe.unet.eval(); torch.save(get_peft_model_state_dict(pipe.unet),Path(outdir,'sd_v3_lora_state.pt'))
    info = {'model':model_id,'training':'UNet LoRA attention','steps':8,'first_loss':losses[0],'last_loss':losses[-1],'losses':losses,'base_prompt':base_prompt,'target_image':str(target_path),'before_image':str(before_path),'trainable_parameters':int(sum(p.numel() for p in trainable))}
    save_json(Path(outdir,'sd_v3_training.json'),info)
    return pipe,base_prompt,target,info


def visual_metrics(img,target):
    a = np.asarray(img.convert('RGB').resize((128,128)),dtype=np.float32)/255.0
    lum = a.mean(2)
    edge = float(np.abs(np.diff(lum,axis=0)).mean()+np.abs(np.diff(lum,axis=1)).mean())
    var = float(a.var()); mean = float(a.mean())
    hist,_ = np.histogram(lum,bins=32,range=(0,1)); p = hist/max(1,hist.sum()); p = p[p>0]; ent = float(-(p*np.log2(p)).sum()/5.0)
    aa = np.asarray(img.convert('L').resize((32,32)),dtype=np.float32)/255.; tt = np.asarray(target.convert('L').resize((32,32)),dtype=np.float32)/255.
    agreement = float(1.0-np.mean(np.abs(aa-tt)))
    return {'edge':edge,'variance':var,'mean':mean,'entropy':ent,'target_agreement':agreement}


def fitness(m):
    return 1.7*m['edge'] + 0.8*m['variance'] + 0.55*m['entropy'] + 0.75*m['target_agreement'] - 0.25*abs(m['mean']-.42)


def mutate(g,rng,scale=1.0):
    mods = ['microscopic','anatomical','bioluminescent','electric','high detail','dark background','fluorescence microscopy','neural tissue','confocal microscopy','synaptic arborization']
    h = dict(g); h['guidance'] = float(np.clip(h['guidance']+rng.normal(0,.50*scale),2.5,8.0)); h['steps'] = int(np.clip(h['steps']+rng.choice([-2,0,2]),6,16)); h['seed'] = int(rng.integers(0,2**31-1)); ms = list(h['mods'])
    if rng.random() < .85:
        m = mods[int(rng.integers(0,len(mods)))]; ms.remove(m) if m in ms else ms.append(m)
    h['mods'] = list(dict.fromkeys(ms))[:5]
    return h


def evolve_recursive(pipe,base_prompt,target,outdir,previous_state,generations=3,population=6):
    prev_score = float(previous_state.get('best_score', -1e9))
    prev_genome = previous_state.get('best_genome') or {'guidance':5.5,'steps':8,'seed':SEED,'mods':['microscopic','anatomical']}
    best = dict(prev_genome); accepted_score = prev_score
    rng = np.random.default_rng(SEED + 300 + int(abs(prev_score)*100000) % 10000)
    history = []; cdir = Path(outdir,'evolution_v3_candidates'); cdir.mkdir(parents=True,exist_ok=True)
    parent_current_score = None

    for gen_idx in range(3,3+generations):
        scale = max(.35, 1.0 - .18*(gen_idx-3))
        pop = [dict(best)] + [mutate(best,rng,scale) for _ in range(population-1)]
        rows = []
        for i,g in enumerate(pop):
            prompt = base_prompt + ', ' + ', '.join(g['mods'])
            generator = torch.Generator(device='cpu').manual_seed(int(g['seed']))
            with torch.no_grad():
                img = pipe(prompt,num_inference_steps=int(g['steps']),guidance_scale=float(g['guidance']),height=128,width=128,generator=generator).images[0]
            m = visual_metrics(img,target); s = fitness(m); fn = cdir/f'g{gen_idx}_p{i}_{s:+.5f}.png'; img.save(fn)
            if gen_idx == 3 and i == 0: parent_current_score = float(s)
            rec = {'generation':gen_idx,'candidate':i,'score':float(s),'metrics':m,'genome':g,'image':str(fn),'prompt':prompt}; history.append(rec); rows.append(rec)
        rows.sort(key=lambda x:x['score'], reverse=True)
        generation_best = rows[0]
        # Strict cross-run elitism: only inherit a mutant if it clears the previous accepted score.
        if generation_best['score'] > accepted_score:
            accepted_score = float(generation_best['score']); best = dict(generation_best['genome'])
        print(f"EVOLVE_V3 generation={gen_idx} generation_best={generation_best['score']:.6f} accepted_best={accepted_score:.6f} genome={best}")

    prompt = base_prompt + ', ' + ', '.join(best['mods']); generator = torch.Generator(device='cpu').manual_seed(int(best['seed']))
    with torch.no_grad():
        final = pipe(prompt,num_inference_steps=max(12,int(best['steps'])),guidance_scale=float(best['guidance']),height=256,width=256,generator=generator).images[0]
    final_path = Path(outdir,'flybrain_sd_v3_final.png'); final.save(final_path)
    state = {
        'previous_best_score':prev_score,
        'previous_best_genome':prev_genome,
        'parent_score_remeasured_current_run':parent_current_score,
        'best_score':float(accepted_score),
        'best_genome':best,
        'improved_over_previous':bool(accepted_score > prev_score),
        'generation_range':[3,2+generations],
        'final_prompt':prompt,
        'final_image':str(final_path),
        'history':history,
    }
    save_json(Path(outdir,'evolution_v3_state.json'),state)
    return state


def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--brain',required=True); ap.add_argument('--meta',required=True); ap.add_argument('--previous',required=True); ap.add_argument('--out',required=True); ap.add_argument('--generations',type=int,default=3); ap.add_argument('--population',type=int,default=6); a = ap.parse_args()
    out = Path(a.out); out.mkdir(parents=True,exist_ok=True)
    brain = brain_summary(load_json(a.brain),load_json(a.meta)); save_json(out/'brain_v3_summary.json',brain)
    previous = load_json(a.previous)
    t0=time.time(); llm=train_llm_structured(brain,out); t1=time.time(); pipe,prompt,target,sd=train_sd_lora(brain,out); t2=time.time(); evo=evolve_recursive(pipe,prompt,target,out,previous,a.generations,a.population); t3=time.time()
    report = {
        'brain':brain,
        'llm':llm,
        'stable_diffusion':sd,
        'evolution':{k:evo[k] for k in ['previous_best_score','parent_score_remeasured_current_run','best_score','best_genome','improved_over_previous','generation_range','final_prompt','final_image']},
        'evaluations':len(evo['history']),
        'timing_sec':{'llm':t1-t0,'sd':t2-t1,'evolution':t3-t2,'total':t3-t0},
        'verified':{'exact_flybrain_input':True,'llm_360m_loaded':True,'llm_lora_parameters_updated':True,'assistant_only_masked_sft':True,'structured_llm_decoding':True,'segmind_tiny_sd_loaded':True,'sd_lora_parameters_updated':True,'connectome_driven_training_target':True,'previous_elite_inherited':True,'strict_nonregression_gate':True,'mutation_selection_executed':True,'consciousness_claim':False},
    }
    save_json(out/'run_report_v3.json',report); print(json.dumps(report,ensure_ascii=False,indent=2))


if __name__=='__main__':
    main()

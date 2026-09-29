#!/usr/bin/env python3
from __future__ import annotations

import gc, gzip, json, math, os, random, shutil, struct, time
from pathlib import Path
import numpy as np

ROOT = Path('.')
OUT = Path('fly-evo-v3-results')
OUT.mkdir(parents=True, exist_ok=True)
OLD_STATE = Path('fly-evo-v2-results/evolution_state.json')
STATE = OUT / 'evolution_state_v3.json'
SEED = 20260929
random.seed(SEED)
np.random.seed(SEED)


def dump(path: Path, obj):
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding='utf-8')


def parse_connectome(path: Path):
    raw = gzip.open(path, 'rb').read()
    n, e = struct.unpack_from('<II', raw, 0)
    edge_dt = np.dtype([('pre','<u4'),('post','<u4'),('w','<f4')])
    meta_dt = np.dtype([('region','u1'),('group','<u2')])
    edges = np.frombuffer(raw, dtype=edge_dt, count=e, offset=8)
    meta = np.frombuffer(raw, dtype=meta_dt, count=n, offset=8 + e*12)
    g = int(meta['group'].max()) + 1
    pg = meta['group'][edges['pre']].astype(np.int64)
    qg = meta['group'][edges['post']].astype(np.int64)
    ew = edges['w'].astype(np.float64)
    cw = np.sign(ew) * np.log1p(np.abs(ew))
    W = np.bincount(pg*g+qg, weights=cw, minlength=g*g).reshape(g,g)
    denom = np.sum(np.abs(W), axis=1, keepdims=True)
    denom[denom < 1e-12] = 1.0
    Wn = W / denom
    sizes = np.bincount(meta['group'], minlength=g)
    greg = np.full(g,255,dtype=np.uint8)
    for gi in range(g):
        idx=np.flatnonzero(meta['group']==gi)
        if idx.size:
            vals,cnts=np.unique(meta['region'][idx],return_counts=True)
            greg[gi]=vals[np.argmax(cnts)]
    a=np.zeros(g,dtype=np.float64)
    sens=np.flatnonzero(greg==0)
    if sens.size:
        z=np.sqrt(sizes[sens].astype(np.float64)+1)
        z/=max(1.0,float(z.max()))
        a[sens]=0.35+0.65*z
    traj=[]
    for t in range(24):
        drive=np.zeros(g)
        if sens.size:
            drive[sens]=(0.055+0.018*math.sin(t*0.73))*a[sens]
        a=np.tanh(0.71*a+1.37*(a@Wn)+drive)
        traj.append(a.copy())
    reg=[float(np.mean(np.abs(a[greg==r]))) if np.any(greg==r) else 0.0 for r in range(4)]
    sig=np.array([float(a.mean()),float(a.std()),float(a.max()),float(a.min())]+reg,dtype=np.float64)
    stats={'neurons':int(n),'edges':int(e),'group_slots':int(g),'populated_group_ids':int(np.sum(sizes>0)),
           'region_counts':{str(r):int(np.sum(meta['region']==r)) for r in range(4)},'brain_signature':sig.tolist()}
    np.savez_compressed(OUT/'connectome_controller_v3.npz',W=W,trajectory=np.stack(traj),signature=sig)
    dump(OUT/'connectome_stats.json',stats)
    return stats,sig


def old_generation_and_text():
    gen=8; text=''; genes=None
    if OLD_STATE.exists():
        try:
            s=json.loads(OLD_STATE.read_text(encoding='utf-8'))
            gen=int(s.get('generation',8)); text=str(s.get('llm',{}).get('text','')); genes=s.get('llm',{}).get('genes')
        except Exception:
            pass
    if STATE.exists():
        try:
            s=json.loads(STATE.read_text(encoding='utf-8'))
            gen=max(gen,int(s.get('generation',gen)))
        except Exception:
            pass
    return gen,text,genes


def text_fitness(text: str):
    keys=['초파리','connectome','LLM','Stable Diffusion','뉴런','보상','진화']
    low=text.lower()
    coverage=sum(k.lower() in low for k in keys)/len(keys)
    order_terms=['입력','뇌활성','생성','평가','선택','돌연변이']
    pos=[text.find(x) for x in order_terms]
    valid=sum(p>=0 for p in pos)/len(pos)
    strictly=1.0 if all(pos[i]>=0 and pos[i]<pos[i+1] for i in range(len(pos)-1)) else 0.0
    n=len(text)
    length=max(0.0,1.0-abs(n-520)/520)
    toks=[x for x in text.replace('\n',' ').split() if x]
    big=list(zip(toks,toks[1:]))
    diversity=len(set(big))/max(1,len(big))
    korean=sum('가'<=c<='힣' for c in text)/max(1,len(text))
    score=.34*coverage+.22*(.55*valid+.45*strictly)+.15*length+.17*diversity+.12*min(1.0,korean/.35)
    return float(score)


def run_llm(sig, start_gen, inherited_text, inherited_genes):
    import torch
    from transformers import AutoTokenizer, AutoModelForCausalLM
    model_id='Qwen/Qwen2.5-1.5B-Instruct'
    torch.set_num_threads(max(1,min(4,os.cpu_count() or 2)))
    tok=AutoTokenizer.from_pretrained(model_id)
    model=AutoModelForCausalLM.from_pretrained(model_id,torch_dtype=torch.float32,low_cpu_mem_usage=True)
    model.eval()
    brain=np.tanh(sig)
    if inherited_genes:
        champion={'temperature':float(np.clip(inherited_genes.get('temperature',.75),.25,1.15)),
                  'top_p':float(np.clip(inherited_genes.get('top_p',.88),.62,.99)),
                  'rep':float(np.clip(inherited_genes.get('rep',1.08),1.0,1.22)),
                  'max_new':int(np.clip(inherited_genes.get('max_new',170),120,220))}
    else:
        champion={'temperature':float(np.clip(.62+.22*abs(brain[1]),.3,1.1)),
                  'top_p':float(np.clip(.84+.08*abs(brain[5]),.65,.98)),
                  'rep':1.07,'max_new':170}
    best_text=inherited_text or ''
    best_score=text_fitness(best_text) if best_text else -1.0
    initial_best=best_score
    system='너는 초파리 connectome과 생성형 AI를 결합하는 연구 엔지니어다. 과장하지 말고 실제 구현의 데이터 흐름, 보상, 선택, 돌연변이를 명확히 설명한다.'
    user=('초파리 FlyWire connectome을 실제 제어기/보상 회로로 사용하고 오픈소스 LLM과 Stable Diffusion을 결합한 진화형 AI 한 사이클을 한국어로 설명하라. '
          "반드시 '초파리', 'connectome', 'LLM', 'Stable Diffusion', '뉴런', '보상', '진화'를 포함하고, "
          "'입력 → 뇌활성 → 생성 → 평가 → 선택 → 돌연변이' 순서를 정확히 지켜라. 각 단계가 실제 코드에서 무엇을 바꾸는지도 설명하라.")
    prompt=tok.apply_chat_template([{'role':'system','content':system},{'role':'user','content':user}],tokenize=False,add_generation_prompt=True)
    inp=tok(prompt,return_tensors='pt')
    rng=np.random.default_rng(SEED+start_gen*101)
    history=[]
    for local in range(4):
        gen=start_gen+local+1
        pop=[champion.copy()]
        # one mutant per generation: strong model makes each candidate expensive on CPU
        m={'temperature':float(np.clip(champion['temperature']+rng.normal(0,.11),.25,1.2)),
           'top_p':float(np.clip(champion['top_p']+rng.normal(0,.045),.60,.995)),
           'rep':float(np.clip(champion['rep']+rng.normal(0,.025),1.0,1.22)),
           'max_new':int(np.clip(champion['max_new']+rng.normal(0,18),120,224))}
        pop.append(m)
        rows=[]
        for i,g in enumerate(pop):
            torch.manual_seed(SEED+gen*37+i)
            with torch.inference_mode():
                out=model.generate(**inp,do_sample=True,temperature=g['temperature'],top_p=g['top_p'],repetition_penalty=g['rep'],max_new_tokens=g['max_new'],pad_token_id=tok.eos_token_id)
            txt=tok.decode(out[0][inp['input_ids'].shape[1]:],skip_special_tokens=True).strip()
            sc=text_fitness(txt)
            row={'generation':gen,'candidate':i,'genes':g,'score':sc,'text':txt}
            rows.append(row)
            if sc>best_score:
                best_score=sc; best_text=txt; champion=g.copy()
        rows.sort(key=lambda x:x['score'],reverse=True)
        history.extend(rows)
        print('V3_LLM_GEN',gen,'GEN_BEST',rows[0]['score'],'BEST_EVER',best_score)
    (OUT/'llm_evolved.txt').write_text(best_text+'\n',encoding='utf-8')
    dump(OUT/'llm_evolution.json',history)
    del model,tok,inp
    gc.collect()
    # free large Qwen cache before diffusion download to stay within runner disk/memory
    qcache=Path(os.environ.get('HF_HOME','/tmp/hf_cache'))/'hub'/'models--Qwen--Qwen2.5-1.5B-Instruct'
    if qcache.exists(): shutil.rmtree(qcache,ignore_errors=True)
    return {'model':model_id,'initial_score':initial_best,'score':best_score,'text':best_text,'genes':champion,'history':history}


def proxy_metrics(im):
    ar=np.asarray(im.convert('RGB'),dtype=np.float32)/255.0
    gray=ar.mean(2)
    hist,_=np.histogram(gray,bins=64,range=(0,1)); p=hist.astype(np.float64)/max(1,hist.sum()); p=p[p>0]
    entropy=float(-(p*np.log2(p)).sum()/6.0)
    contrast=float(gray.std())
    edge=float((np.abs(np.diff(gray,axis=0)).mean()+np.abs(np.diff(gray,axis=1)).mean())/2)
    saturation=float(np.std(ar,axis=2).mean())
    proxy=.30*min(1,entropy)+.25*min(1,contrast/.24)+.28*min(1,edge/.12)+.17*min(1,saturation/.20)
    return {'entropy':entropy,'contrast':contrast,'edge':edge,'saturation':saturation,'proxy':float(proxy)}


def clip_similarity(model,proc,image,prompt,torch):
    inputs=proc(text=[prompt],images=[image],return_tensors='pt',padding=True)
    with torch.inference_mode():
        out=model(**inputs)
        a=out.image_embeds/out.image_embeds.norm(dim=-1,keepdim=True)
        b=out.text_embeds/out.text_embeds.norm(dim=-1,keepdim=True)
        cos=float((a*b).sum().item())
    return cos


def run_image(sig,start_gen):
    import torch
    from diffusers import AutoPipelineForText2Image
    from transformers import CLIPModel, CLIPProcessor
    from PIL import Image,ImageDraw
    torch.set_num_threads(max(1,min(4,os.cpu_count() or 2)))
    sd_id='stabilityai/sd-turbo'
    clip_id='openai/clip-vit-base-patch32'
    clip_model=CLIPModel.from_pretrained(clip_id)
    clip_model.eval(); clip_proc=CLIPProcessor.from_pretrained(clip_id)
    pipe=AutoPipelineForText2Image.from_pretrained(sd_id,torch_dtype=torch.float32)
    if hasattr(pipe,'safety_checker'): pipe.safety_checker=None
    pipe.set_progress_bar_config(disable=True); pipe=pipe.to('cpu')
    brain=np.tanh(sig)
    base_prompt=('macro scientific portrait of a Drosophila fruit fly, visible transparent brain with intricate neural connectome, '
                 'glowing synapses, biologically inspired circuitry, high detail, photorealistic, laboratory visualization')
    modifiers=['volumetric microscopy lighting','precise anatomical overlay','bioluminescent axon pathways','ultra-detailed compound eyes','clean dark laboratory background','cinematic macro optics']
    idx=int(abs(brain[2])*10000)%len(modifiers)
    champion={'steps':2,'seed':int(SEED+abs(brain[3])*1_000_000)%2_147_000_000,'modifier':modifiers[idx]}
    best=None; history=[]; saved=[]
    rng=np.random.default_rng(SEED+start_gen*211)
    for local in range(4):
        gen=start_gen+local+1
        mutant={'steps':int(np.clip(champion['steps']+rng.choice([-1,0,1]),1,4)),
                'seed':int(rng.integers(1,2_147_000_000)),
                'modifier':modifiers[int(rng.integers(0,len(modifiers)))]}
        pop=[champion.copy(),mutant]
        rows=[]
        for i,g in enumerate(pop):
            prompt=base_prompt+', '+g['modifier']
            generator=torch.Generator(device='cpu').manual_seed(g['seed'])
            with torch.inference_mode():
                im=pipe(prompt=prompt,width=512,height=512,num_inference_steps=g['steps'],guidance_scale=0.0,generator=generator).images[0]
            pm=proxy_metrics(im)
            clip=clip_similarity(clip_model,clip_proc,im,prompt,torch)
            clip01=(clip+1.0)/2.0
            score=float(.78*clip01+.22*pm['proxy'])
            name=f'g{gen}_c{i}'
            im.save(OUT/f'sd_{name}.png')
            row={'generation':gen,'candidate':i,'genes':g,'clip_cosine':clip,'clip_01':clip01,'proxy_metrics':pm,'score':score,'prompt':prompt,'file':f'sd_{name}.png'}
            rows.append(row); saved.append((name,im.copy(),row))
            if best is None or score>best['score']:
                best=row; champion=g.copy(); im.save(OUT/'sd_selected.png')
        rows.sort(key=lambda x:x['score'],reverse=True); history.extend(rows)
        print('V3_SD_GEN',gen,'GEN_BEST',rows[0]['score'],'BEST_EVER',best['score'])
    # contact sheet, max 8 images
    thumb=256; label_h=42
    sheet=Image.new('RGB',(thumb*4,(thumb+label_h)*2),'white'); draw=ImageDraw.Draw(sheet)
    for k,(name,im,row) in enumerate(saved[:8]):
        x=(k%4)*thumb; y=(k//4)*(thumb+label_h)
        sheet.paste(im.resize((thumb,thumb)),(x,y)); draw.text((x+6,y+thumb+5),f'{name} score={row["score"]:.3f} clip={row["clip_cosine"]:.3f}',fill='black')
    sheet.save(OUT/'sd_contact_sheet.png')
    dump(OUT/'sd_evolution.json',{'model':sd_id,'clip_model':clip_id,'fitness':'0.78*CLIP_mapped + 0.22*visual_proxy','history':history,'winner':best})
    del pipe,clip_model,clip_proc
    gc.collect()
    return {'model':sd_id,'clip_model':clip_id,'score':best['score'],'winner':best,'genes':champion,'history':history}


def main():
    t0=time.time()
    fly=Path(os.environ.get('FLY_CONNECTOME','/tmp/flybrain/data/connectome.bin.gz'))
    stats,sig=parse_connectome(fly)
    assert stats['neurons']==139255 and stats['edges']==2698236
    start_gen,inherited_text,inherited_genes=old_generation_and_text()
    # v3 is intended to continue 8 -> 12; if rerun, it continues from its own saved generation.
    if STATE.exists():
        try:
            old=json.loads(STATE.read_text(encoding='utf-8'))
            start_gen=max(start_gen,int(old.get('generation',start_gen)))
            inherited_text=str(old.get('llm',{}).get('text',inherited_text))
            inherited_genes=old.get('llm',{}).get('genes',inherited_genes)
        except Exception: pass
    llm=run_llm(sig,start_gen,inherited_text,inherited_genes)
    sd=run_image(sig,start_gen)
    end_gen=start_gen+4
    state={'generation':end_gen,'connectome':stats,'llm':{'model':llm['model'],'score':llm['score'],'text':llm['text'],'genes':llm['genes']},
           'sd':{'model':sd['model'],'clip_model':sd['clip_model'],'score':sd['score'],'genes':sd['genes'],'winner':sd['winner']}}
    dump(STATE,state)
    result={'status':'SUCCESS','generation_start':start_gen,'generation_end':end_gen,'connectome':stats,
            'upgrade':{'llm_from':'Qwen/Qwen2.5-0.5B-Instruct','llm_to':llm['model'],'sd_from':'segmind/tiny-sd','sd_to':sd['model'],'semantic_evaluator':sd['clip_model']},
            'llm':{'inherited_v2_score':llm['initial_score'],'v3_best_score':llm['score'],'champion_genes':llm['genes']},
            'image':{'v3_best_score':sd['score'],'winner':sd['winner'],'fitness_note':'v3 score uses CLIP semantic alignment plus visual proxy; do not compare numerically to v2 image score'},
            'elapsed_seconds':time.time()-t0,
            'learning':'pretrained LLM and diffusion weights remain frozen; the full FlyBrain-derived controller conditions evolutionary search; best-ever champion is persisted'}
    dump(OUT/'result.json',result)
    (OUT/'summary.txt').write_text('\n'.join([
        'FLY CONNECTOME x QWEN 1.5B x SD-TURBO x CLIP — V3',
        f'generation {start_gen} -> {end_gen}',f'neurons={stats["neurons"]} edges={stats["edges"]}',
        f'LLM best={llm["score"]:.6f}',f'Image best={sd["score"]:.6f} clip={sd["winner"]["clip_cosine"]:.6f}',
        f'elapsed={result["elapsed_seconds"]:.2f}s'])+'\n',encoding='utf-8')
    print(json.dumps(result,ensure_ascii=False,indent=2))

if __name__=='__main__': main()

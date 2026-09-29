#!/usr/bin/env python3
from __future__ import annotations

import gc, gzip, json, math, os, random, shutil, struct, time
from pathlib import Path
import numpy as np

OUT = Path('fly-evo-v3-results')
OUT.mkdir(parents=True, exist_ok=True)
V2_STATE = Path('fly-evo-v2-results/evolution_state.json')
V3_STATE = OUT / 'evolution_state_v3.json'
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

    # The binary only needs to encode groups that actually contain neurons. The
    # repository metadata declares all logical group slots, including empty ones.
    declared_groups = int(meta['group'].max()) + 1
    meta_json_path = path.parent / 'neuron_meta.json'
    if meta_json_path.exists():
        try:
            declared_groups = max(declared_groups, int(json.loads(meta_json_path.read_text())['group_count']))
        except Exception:
            pass
    g = declared_groups

    pg = meta['group'][edges['pre']].astype(np.int64)
    qg = meta['group'][edges['post']].astype(np.int64)
    ew = edges['w'].astype(np.float64)
    cw = np.sign(ew) * np.log1p(np.abs(ew))
    W = np.bincount(pg*g + qg, weights=cw, minlength=g*g).reshape(g,g)
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
    stats={
        'neurons':int(n),'edges':int(e),'group_slots':int(g),'populated_group_ids':int(np.sum(sizes>0)),
        'region_counts':{str(r):int(np.sum(meta['region']==r)) for r in range(4)},
        'brain_signature':sig.tolist()
    }
    np.savez_compressed(OUT/'connectome_controller_v3.npz',W=W,trajectory=np.stack(traj),signature=sig)
    dump(OUT/'connectome_stats.json',stats)
    return stats,sig


def load_prior_state():
    prior={}
    if V2_STATE.exists():
        try:
            prior=json.loads(V2_STATE.read_text(encoding='utf-8'))
        except Exception:
            prior={}
    if V3_STATE.exists():
        try:
            v3=json.loads(V3_STATE.read_text(encoding='utf-8'))
            if int(v3.get('generation',0)) >= int(prior.get('generation',0)):
                prior=v3
        except Exception:
            pass
    return prior


def text_fitness(text: str):
    low=text.lower()
    keys=['초파리','connectome','llm','stable diffusion','뉴런','보상','진화']
    coverage=sum(k in low for k in keys)/len(keys)

    # Strongly reward an explicit implementation order rather than loose keyword soup.
    labels=['[입력]','[뇌활성]','[생성]','[평가]','[선택]','[돌연변이]']
    pos=[text.find(x) for x in labels]
    label_coverage=sum(p>=0 for p in pos)/len(pos)
    strict=1.0 if all(pos[i]>=0 and pos[i]<pos[i+1] for i in range(len(pos)-1)) else 0.0

    implementation_terms=['가중치 고정','sampling','seed','clip','fitness','파라미터']
    implementation=sum(k in low for k in implementation_terms)/len(implementation_terms)
    n=len(text)
    length=max(0.0,1.0-abs(n-700)/700)
    toks=[x for x in text.replace('\n',' ').split() if x]
    big=list(zip(toks,toks[1:]))
    diversity=len(set(big))/max(1,len(big))

    # Known factual failure modes seen in earlier generations get an explicit penalty.
    bad=['척추동물','전자 시스템','openai에서 개발된 stable diffusion','2014년에 처음 소개','miyawaki']
    penalty=0.06*sum(x in low for x in bad)
    score=(.23*coverage + .28*(.45*label_coverage+.55*strict) + .20*implementation +
           .12*length + .17*diversity - penalty)
    return float(np.clip(score,0,1))


def run_llm(sig,start_gen,prior_llm):
    import torch
    from transformers import AutoTokenizer, AutoModelForCausalLM
    model_id='Qwen/Qwen2.5-1.5B-Instruct'
    torch.set_num_threads(max(1,min(4,os.cpu_count() or 2)))
    tok=AutoTokenizer.from_pretrained(model_id)
    model=AutoModelForCausalLM.from_pretrained(model_id,torch_dtype=torch.float32,low_cpu_mem_usage=True)
    model.eval()

    brain=np.tanh(sig)
    inherited_genes=(prior_llm or {}).get('genes') or {}
    champion={
        'temperature':float(np.clip(inherited_genes.get('temperature',.62+.22*abs(brain[1])),.25,1.15)),
        'top_p':float(np.clip(inherited_genes.get('top_p',.84+.08*abs(brain[5])),.62,.99)),
        'rep':float(np.clip(inherited_genes.get('rep',1.07),1.0,1.22)),
        'max_new':int(np.clip(inherited_genes.get('max_new',190),150,240))
    }
    best_text=str((prior_llm or {}).get('text',''))
    best_score=text_fitness(best_text) if best_text else -1.0
    initial_best=best_score

    system=(
        '너는 초파리 connectome과 생성형 AI를 결합하는 연구 엔지니어다. '
        '생물학적 connectome 자체와 생성모델의 사전학습 가중치를 혼동하지 않는다. '
        '이번 시스템에서 LLM과 diffusion의 사전학습 가중치는 고정이며, connectome 기반 controller가 생성 파라미터를 진화시킨다는 사실을 정확히 설명한다.'
    )
    user=(
        '다음 여섯 제목을 정확히 이 순서로 한 번씩 써라: [입력] [뇌활성] [생성] [평가] [선택] [돌연변이]. '
        '초파리 FlyBrain connectome의 뉴런/연결에서 축약한 recurrent controller와 오픈소스 LLM, Stable Diffusion을 결합한 실제 한 사이클을 한국어로 설명하라. '
        "반드시 '가중치 고정', 'sampling', 'seed', 'CLIP', 'fitness', '파라미터', '보상', '진화'를 포함하라. "
        'LLM/Stable Diffusion이 connectome 데이터를 직접 재학습했다고 쓰지 말고, controller가 sampling/seed 등 생성 파라미터를 바꾸며 후보를 만들고 fitness로 선택한다고 명시하라.'
    )
    prompt=tok.apply_chat_template([{'role':'system','content':system},{'role':'user','content':user}],tokenize=False,add_generation_prompt=True)
    inp=tok(prompt,return_tensors='pt')
    rng=np.random.default_rng(SEED+start_gen*101)
    history=[]

    for local in range(4):
        gen=start_gen+local+1
        pop=[champion.copy()]
        pop.append({
            'temperature':float(np.clip(champion['temperature']+rng.normal(0,.09),.25,1.15)),
            'top_p':float(np.clip(champion['top_p']+rng.normal(0,.04),.62,.995)),
            'rep':float(np.clip(champion['rep']+rng.normal(0,.022),1.0,1.22)),
            'max_new':int(np.clip(champion['max_new']+rng.normal(0,15),150,240))
        })
        rows=[]
        for i,g in enumerate(pop):
            torch.manual_seed(SEED+gen*37+i)
            with torch.inference_mode():
                out=model.generate(
                    **inp,do_sample=True,temperature=g['temperature'],top_p=g['top_p'],
                    repetition_penalty=g['rep'],max_new_tokens=g['max_new'],pad_token_id=tok.eos_token_id
                )
            txt=tok.decode(out[0][inp['input_ids'].shape[1]:],skip_special_tokens=True).strip()
            sc=text_fitness(txt)
            row={'generation':gen,'candidate':i,'genes':g,'score':sc,'text':txt}
            rows.append(row)
            if sc>best_score:
                best_score=sc; best_text=txt; champion=g.copy()
        rows.sort(key=lambda x:x['score'],reverse=True)
        history.extend(rows)
        print('V31_LLM_GEN',gen,'GEN_BEST',rows[0]['score'],'BEST_EVER',best_score,flush=True)

    (OUT/'llm_evolved.txt').write_text(best_text+'\n',encoding='utf-8')
    dump(OUT/'llm_evolution_latest.json',history)
    del model,tok,inp
    gc.collect()
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
        return float((a*b).sum().item())


def run_image(sig,start_gen,prior_sd):
    import torch
    from diffusers import AutoPipelineForText2Image
    from transformers import CLIPModel, CLIPProcessor
    from PIL import Image,ImageDraw
    torch.set_num_threads(max(1,min(4,os.cpu_count() or 2)))
    sd_id='stabilityai/sd-turbo'
    clip_id='openai/clip-vit-base-patch32'
    clip_model=CLIPModel.from_pretrained(clip_id); clip_model.eval()
    clip_proc=CLIPProcessor.from_pretrained(clip_id)
    pipe=AutoPipelineForText2Image.from_pretrained(sd_id,torch_dtype=torch.float32)
    if hasattr(pipe,'safety_checker'): pipe.safety_checker=None
    pipe.set_progress_bar_config(disable=True); pipe=pipe.to('cpu')

    brain=np.tanh(sig)
    base_prompt=('macro scientific portrait of a Drosophila fruit fly, visible transparent brain with intricate neural connectome, '
                 'glowing synapses, biologically inspired circuitry, high detail, photorealistic, laboratory visualization')
    modifiers=['volumetric microscopy lighting','precise anatomical overlay','bioluminescent axon pathways','ultra-detailed compound eyes','clean dark laboratory background','cinematic macro optics']
    idx=int(abs(brain[2])*10000)%len(modifiers)

    prev=(prior_sd or {}) if (prior_sd or {}).get('model')==sd_id else {}
    champion=(prev.get('genes') or {'steps':2,'seed':int(SEED+abs(brain[3])*1_000_000)%2_147_000_000,'modifier':modifiers[idx]}).copy()
    champion['steps']=int(np.clip(champion.get('steps',2),1,4))
    champion['seed']=int(champion.get('seed',SEED))
    champion['modifier']=champion.get('modifier',modifiers[idx])
    best=prev.get('winner') if prev.get('winner') else None
    best_score=float(prev.get('score',-1.0)) if best is not None else -1.0
    initial_best=best_score

    history=[]; saved=[]
    rng=np.random.default_rng(SEED+start_gen*211)
    for local in range(4):
        gen=start_gen+local+1
        mutant={
            'steps':int(np.clip(champion['steps']+rng.choice([-1,0,1]),1,4)),
            'seed':int(rng.integers(1,2_147_000_000)),
            'modifier':modifiers[int(rng.integers(0,len(modifiers)))]
        }
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
            if score>best_score:
                best_score=score; best=row; champion=g.copy(); im.save(OUT/'sd_selected.png')
        rows.sort(key=lambda x:x['score'],reverse=True)
        history.extend(rows)
        print('V31_SD_GEN',gen,'GEN_BEST',rows[0]['score'],'BEST_EVER',best_score,flush=True)

    # If no new image beat the persisted champion, the old sd_selected.png remains untouched.
    thumb=256; label_h=42
    sheet=Image.new('RGB',(thumb*4,(thumb+label_h)*2),'white'); draw=ImageDraw.Draw(sheet)
    for k,(name,im,row) in enumerate(saved[:8]):
        x=(k%4)*thumb; y=(k//4)*(thumb+label_h)
        sheet.paste(im.resize((thumb,thumb)),(x,y))
        draw.text((x+6,y+thumb+5),f'{name} score={row["score"]:.3f} clip={row["clip_cosine"]:.3f}',fill='black')
    sheet.save(OUT/'sd_contact_sheet_latest.png')
    dump(OUT/'sd_evolution_latest.json',{'model':sd_id,'clip_model':clip_id,'fitness':'0.78*CLIP_mapped + 0.22*visual_proxy','history':history,'winner':best})
    del pipe,clip_model,clip_proc
    gc.collect()
    return {'model':sd_id,'clip_model':clip_id,'initial_score':initial_best,'score':best_score,'winner':best,'genes':champion,'history':history}


def main():
    t0=time.time()
    fly=Path(os.environ.get('FLY_CONNECTOME','/tmp/flybrain/data/connectome.bin.gz'))
    stats,sig=parse_connectome(fly)
    assert stats['neurons']==139255 and stats['edges']==2698236
    assert stats['group_slots']==63 and stats['populated_group_ids']==32

    prior=load_prior_state()
    start_gen=max(8,int(prior.get('generation',8)))
    prior_llm=prior.get('llm',{})
    prior_sd=prior.get('sd',{})

    llm=run_llm(sig,start_gen,prior_llm)
    sd=run_image(sig,start_gen,prior_sd)
    end_gen=start_gen+4

    state={
        'generation':end_gen,'connectome':stats,
        'llm':{'model':llm['model'],'score':llm['score'],'text':llm['text'],'genes':llm['genes'],'fitness_version':'v3.1'},
        'sd':{'model':sd['model'],'clip_model':sd['clip_model'],'score':sd['score'],'genes':sd['genes'],'winner':sd['winner'],'fitness_version':'v3'}
    }
    dump(V3_STATE,state)
    result={
        'status':'SUCCESS','generation_start':start_gen,'generation_end':end_gen,'connectome':stats,
        'models':{'llm':llm['model'],'diffusion':sd['model'],'semantic_evaluator':sd['clip_model']},
        'llm':{'before_score_under_v31':llm['initial_score'],'after_score_v31':llm['score'],'improved':llm['score']>llm['initial_score'],'champion_genes':llm['genes']},
        'image':{'before_score_v3':sd['initial_score'],'after_score_v3':sd['score'],'improved':sd['score']>sd['initial_score'],'winner':sd['winner']},
        'elapsed_seconds':time.time()-t0,
        'learning':'pretrained Qwen/SD-Turbo weights frozen; 139255-neuron/2698236-edge FlyBrain is reduced through all 63 declared group slots into a recurrent controller; persistent best-ever champions seed the next run'
    }
    dump(OUT/'result.json',result)
    (OUT/'summary.txt').write_text('\n'.join([
        'FLY CONNECTOME PERSISTENT NEUROEVOLUTION V3.1',
        f'generation {start_gen} -> {end_gen}',
        f'neurons={stats["neurons"]} edges={stats["edges"]} groups={stats["group_slots"]} populated={stats["populated_group_ids"]}',
        f'LLM {llm["initial_score"]:.6f} -> {llm["score"]:.6f}',
        f'Image {sd["initial_score"]:.6f} -> {sd["score"]:.6f}',
        f'elapsed={result["elapsed_seconds"]:.2f}s'])+'\n',encoding='utf-8')
    print(json.dumps(result,ensure_ascii=False,indent=2))

if __name__=='__main__':
    main()

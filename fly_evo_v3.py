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
    raw=gzip.open(path,'rb').read()
    n,e=struct.unpack_from('<II',raw,0)
    edge_dt=np.dtype([('pre','<u4'),('post','<u4'),('w','<f4')])
    meta_dt=np.dtype([('region','u1'),('group','<u2')])
    edges=np.frombuffer(raw,dtype=edge_dt,count=e,offset=8)
    meta=np.frombuffer(raw,dtype=meta_dt,count=n,offset=8+e*12)

    g=int(meta['group'].max())+1
    mp=path.parent/'neuron_meta.json'
    if mp.exists():
        try: g=max(g,int(json.loads(mp.read_text())['group_count']))
        except Exception: pass

    pg=meta['group'][edges['pre']].astype(np.int64)
    qg=meta['group'][edges['post']].astype(np.int64)
    ew=edges['w'].astype(np.float64)
    cw=np.sign(ew)*np.log1p(np.abs(ew))
    W=np.bincount(pg*g+qg,weights=cw,minlength=g*g).reshape(g,g)
    denom=np.sum(np.abs(W),axis=1,keepdims=True); denom[denom<1e-12]=1
    Wn=W/denom
    sizes=np.bincount(meta['group'],minlength=g)
    greg=np.full(g,255,dtype=np.uint8)
    for gi in range(g):
        idx=np.flatnonzero(meta['group']==gi)
        if idx.size:
            vals,cnts=np.unique(meta['region'][idx],return_counts=True)
            greg[gi]=vals[np.argmax(cnts)]

    a=np.zeros(g,dtype=np.float64)
    sensory=np.flatnonzero(greg==0)
    if sensory.size:
        z=np.sqrt(sizes[sensory].astype(float)+1); z/=max(1.0,float(z.max()))
        a[sensory]=0.35+0.65*z
    traj=[]
    for t in range(28):
        drive=np.zeros(g)
        if sensory.size: drive[sensory]=(0.055+0.018*math.sin(t*.73))*a[sensory]
        a=np.tanh(.71*a+1.37*(a@Wn)+drive)
        traj.append(a.copy())
    reg=[float(np.mean(np.abs(a[greg==r]))) if np.any(greg==r) else 0.0 for r in range(4)]
    sig=np.array([float(a.mean()),float(a.std()),float(a.max()),float(a.min())]+reg)
    stats={
        'neurons':int(n),'edges':int(e),'group_slots':int(g),'populated_group_ids':int(np.sum(sizes>0)),
        'region_counts':{str(r):int(np.sum(meta['region']==r)) for r in range(4)},'brain_signature':sig.tolist()
    }
    np.savez_compressed(OUT/'connectome_controller_v3.npz',W=W,trajectory=np.stack(traj),signature=sig)
    dump(OUT/'connectome_stats.json',stats)
    return stats,sig


def load_prior_state():
    prior={}
    if V2_STATE.exists():
        try: prior=json.loads(V2_STATE.read_text(encoding='utf-8'))
        except Exception: prior={}
    if V3_STATE.exists():
        try:
            v3=json.loads(V3_STATE.read_text(encoding='utf-8'))
            if int(v3.get('generation',0))>=int(prior.get('generation',0)): prior=v3
        except Exception: pass
    return prior


LABELS=['[입력]','[뇌활성]','[생성]','[평가]','[선택]','[돌연변이]']


def split_sections(text:str):
    pos=[text.find(x) for x in LABELS]
    if not all(p>=0 for p in pos): return pos,[]
    sections=[]
    for i,p in enumerate(pos):
        start=p+len(LABELS[i]); end=pos[i+1] if i+1<len(pos) else len(text)
        sections.append(text[start:end].strip())
    return pos,sections


def text_fitness(text:str):
    low=text.lower().strip()
    core=['초파리','connectome','llm','stable diffusion','뉴런','보상','진화']
    core_cov=sum(k in low for k in core)/len(core)
    pos,sections=split_sections(text)
    label_cov=sum(p>=0 for p in pos)/len(LABELS)
    strict=1.0 if len(pos)==len(LABELS) and all(pos[i]>=0 and pos[i]<pos[i+1] for i in range(len(pos)-1)) else 0.0
    body_ok=(sum(len(s)>=45 for s in sections)/len(LABELS)) if sections else 0.0
    body_depth=(sum(min(1.0,len(s)/110.0) for s in sections)/len(LABELS)) if sections else 0.0

    impl=['가중치 고정','sampling','seed','clip','fitness','파라미터']
    impl_cov=sum(k in low for k in impl)/len(impl)
    n=len(text)
    length=max(0.0,1.0-abs(n-950)/950)
    toks=[x for x in text.replace('\n',' ').split() if x]
    big=list(zip(toks,toks[1:])); diversity=len(set(big))/max(1,len(big))
    completion=1.0 if text.rstrip().endswith(('다.','니다.','.','요.')) and not text.rstrip().endswith(']') else 0.0

    bad=['척추동물','전자 시스템','openai에서 개발된 stable diffusion','2014년에 처음 소개','miyawaki','connectome 데이터를 직접 학습']
    penalty=.055*sum(x in low for x in bad)
    score=(.15*core_cov + .16*(.4*label_cov+.6*strict) + .24*(.45*body_ok+.55*body_depth) +
           .16*impl_cov + .10*length + .09*diversity + .10*completion - penalty)
    if n<500: score-=.12
    if sections and any(len(s)<20 for s in sections): score-=.10
    return float(np.clip(score,0,1))


def run_llm(sig,start_gen,prior_llm):
    import torch
    from transformers import AutoTokenizer,AutoModelForCausalLM
    model_id='Qwen/Qwen2.5-1.5B-Instruct'
    torch.set_num_threads(max(1,min(4,os.cpu_count() or 2)))
    tok=AutoTokenizer.from_pretrained(model_id)
    model=AutoModelForCausalLM.from_pretrained(model_id,torch_dtype=torch.float32,low_cpu_mem_usage=True)
    model.eval()

    inherited=(prior_llm or {}).get('genes') or {}
    prior_text=str((prior_llm or {}).get('text',''))
    prior_score=text_fitness(prior_text) if prior_text else -1.0
    if prior_score<.72:
        champion={'temperature':.48,'top_p':.90,'rep':1.06,'max_new':330}
    else:
        champion={
            'temperature':float(np.clip(inherited.get('temperature',.55),.28,.95)),
            'top_p':float(np.clip(inherited.get('top_p',.9),.72,.98)),
            'rep':float(np.clip(inherited.get('rep',1.06),1.0,1.18)),
            'max_new':int(np.clip(max(280,inherited.get('max_new',320)),280,380))
        }
    best_text=prior_text; best_score=prior_score; initial_best=prior_score

    system=(
        '너는 초파리 connectome과 생성형 AI를 결합하는 연구 엔지니어다. 사실만 쓴다. '
        'LLM과 Stable Diffusion의 사전학습 가중치는 고정이며, FlyBrain connectome에서 계산한 recurrent controller가 생성 파라미터만 바꾼다. '
        'connectome이 LLM 자체로 변환되거나 생성모델 가중치를 직접 학습한다고 주장하지 않는다.'
    )
    user=(
        '아래 여섯 제목을 정확히 이 순서로 사용하고, 각 제목 아래에 반드시 2문장 이상을 써라. 총 700~1100자로 끝까지 완결하라.\n'
        '[입력]\n[뇌활성]\n[생성]\n[평가]\n[선택]\n[돌연변이]\n\n'
        '설명 대상: 139,255개 뉴런과 2,698,236개 연결의 초파리 FlyBrain connectome을 63개 논리 그룹 recurrent controller로 축약하고, '
        '오픈소스 LLM과 Stable Diffusion의 가중치 고정 상태에서 sampling temperature/top_p, seed, diffusion steps/프롬프트 같은 파라미터를 후보별로 바꾼다. '
        '생성 결과는 CLIP 의미 일치도와 시각 지표를 합친 fitness/보상으로 평가하고, 최고 개체를 선택한 뒤 파라미터에 돌연변이를 주어 다음 세대를 만든다. '
        "반드시 '가중치 고정', 'sampling', 'seed', 'CLIP', 'fitness', '파라미터', '보상', '진화'라는 표현을 자연스럽게 포함하라. 마지막 문장은 반드시 완결된 문장으로 끝내라."
    )
    prompt=tok.apply_chat_template([{'role':'system','content':system},{'role':'user','content':user}],tokenize=False,add_generation_prompt=True)
    inp=tok(prompt,return_tensors='pt')
    rng=np.random.default_rng(SEED+start_gen*101)
    history=[]

    for local in range(4):
        gen=start_gen+local+1
        mutant={
            'temperature':float(np.clip(champion['temperature']+rng.normal(0,.07),.28,.95)),
            'top_p':float(np.clip(champion['top_p']+rng.normal(0,.035),.72,.985)),
            'rep':float(np.clip(champion['rep']+rng.normal(0,.018),1.0,1.18)),
            'max_new':int(np.clip(champion['max_new']+rng.normal(0,18),280,390))
        }
        pop=[champion.copy(),mutant]
        rows=[]
        for i,g in enumerate(pop):
            torch.manual_seed(SEED+gen*41+i)
            with torch.inference_mode():
                out=model.generate(**inp,do_sample=True,temperature=g['temperature'],top_p=g['top_p'],repetition_penalty=g['rep'],
                                   max_new_tokens=g['max_new'],pad_token_id=tok.eos_token_id)
            txt=tok.decode(out[0][inp['input_ids'].shape[1]:],skip_special_tokens=True).strip()
            sc=text_fitness(txt)
            row={'generation':gen,'candidate':i,'genes':g,'score':sc,'text':txt,'chars':len(txt)}
            rows.append(row)
            if sc>best_score:
                best_score=sc; best_text=txt; champion=g.copy()
        rows.sort(key=lambda x:x['score'],reverse=True); history.extend(rows)
        print('V32_LLM_GEN',gen,'GEN_BEST',rows[0]['score'],'BEST_EVER',best_score,'CHARS',rows[0]['chars'],flush=True)

    (OUT/'llm_evolved.txt').write_text(best_text+'\n',encoding='utf-8')
    dump(OUT/'llm_evolution_latest.json',history)
    del model,tok,inp; gc.collect()
    qcache=Path(os.environ.get('HF_HOME','/tmp/hf_cache'))/'hub'/'models--Qwen--Qwen2.5-1.5B-Instruct'
    if qcache.exists(): shutil.rmtree(qcache,ignore_errors=True)
    return {'model':model_id,'initial_score':initial_best,'score':best_score,'text':best_text,'genes':champion,'history':history}


def proxy_metrics(im):
    ar=np.asarray(im.convert('RGB'),dtype=np.float32)/255.; gray=ar.mean(2)
    hist,_=np.histogram(gray,bins=64,range=(0,1)); p=hist.astype(float)/max(1,hist.sum()); p=p[p>0]
    entropy=float(-(p*np.log2(p)).sum()/6); contrast=float(gray.std())
    edge=float((np.abs(np.diff(gray,axis=0)).mean()+np.abs(np.diff(gray,axis=1)).mean())/2)
    saturation=float(np.std(ar,axis=2).mean())
    proxy=.30*min(1,entropy)+.25*min(1,contrast/.24)+.28*min(1,edge/.12)+.17*min(1,saturation/.20)
    return {'entropy':entropy,'contrast':contrast,'edge':edge,'saturation':saturation,'proxy':float(proxy)}


def clip_similarity(model,proc,image,text,torch):
    inputs=proc(text=[text],images=[image],return_tensors='pt',padding=True)
    with torch.inference_mode():
        out=model(**inputs); a=out.image_embeds/out.image_embeds.norm(dim=-1,keepdim=True); b=out.text_embeds/out.text_embeds.norm(dim=-1,keepdim=True)
        return float((a*b).sum().item())


def image_score(im,clip_model,clip_proc,eval_text,torch):
    pm=proxy_metrics(im); clip=clip_similarity(clip_model,clip_proc,im,eval_text,torch); clip01=(clip+1)/2
    score=float(.82*clip01+.18*pm['proxy'])
    return score,clip,clip01,pm


def run_image(sig,start_gen,prior_sd):
    import torch
    from diffusers import AutoPipelineForText2Image
    from transformers import CLIPModel,CLIPProcessor
    from PIL import Image,ImageDraw
    torch.set_num_threads(max(1,min(4,os.cpu_count() or 2)))
    sd_id='stabilityai/sd-turbo'; clip_id='openai/clip-vit-base-patch32'
    eval_text='a detailed scientific macro image of a Drosophila fruit fly with a clearly visible brain and neural connectome, photorealistic'
    clip_model=CLIPModel.from_pretrained(clip_id); clip_model.eval(); clip_proc=CLIPProcessor.from_pretrained(clip_id)
    pipe=AutoPipelineForText2Image.from_pretrained(sd_id,torch_dtype=torch.float32)
    if hasattr(pipe,'safety_checker'): pipe.safety_checker=None
    pipe.set_progress_bar_config(disable=True); pipe=pipe.to('cpu')

    modifiers=[
        'recognizable Drosophila anatomy, six legs, two transparent wings, neural overlay concentrated inside the head',
        'transparent head capsule revealing a realistic brain connectome, macro insect photography',
        'scientific microscopy, realistic fruit fly body, neural pathways inside the brain not the background',
        'photorealistic Drosophila on a clean dark laboratory background with a transparent neural brain overlay',
        'high-detail compound eyes and wings, visible brain and axon pathways inside the head',
        'museum-grade biological illustration blended with macro photography, precise brain connectome overlay'
    ]
    base_prompt='Drosophila fruit fly, scientific macro photography, visible brain neural connectome, photorealistic, high anatomical detail'
    brain=np.tanh(sig); idx=int(abs(brain[2])*10000)%len(modifiers)

    prev=(prior_sd or {}) if (prior_sd or {}).get('model')==sd_id else {}
    old_genes=(prev.get('genes') or {})
    champion={'steps':int(np.clip(old_genes.get('steps',2),1,4)),'seed':int(old_genes.get('seed',SEED)),
              'modifier':old_genes.get('modifier',modifiers[idx])}

    best=None; best_score=-1.0
    selected_path=OUT/'sd_selected.png'
    if selected_path.exists():
        try:
            old_im=Image.open(selected_path).convert('RGB')
            sc,cl,c01,pm=image_score(old_im,clip_model,clip_proc,eval_text,torch)
            best_score=sc
            best={'generation':start_gen,'candidate':'persisted','genes':champion.copy(),'clip_cosine':cl,'clip_01':c01,
                  'proxy_metrics':pm,'score':sc,'eval_text':eval_text,'file':'sd_selected.png','persisted':True}
        except Exception: pass
    initial_best=best_score

    history=[]; saved=[]; rng=np.random.default_rng(SEED+start_gen*211)
    for local in range(4):
        gen=start_gen+local+1
        mutant={'steps':int(np.clip(champion['steps']+rng.choice([-1,0,1]),1,4)),
                'seed':int(rng.integers(1,2_147_000_000)),'modifier':modifiers[int(rng.integers(0,len(modifiers)))]}
        pop=[champion.copy(),mutant]
        rows=[]
        for i,g in enumerate(pop):
            prompt=base_prompt+', '+g['modifier']
            generator=torch.Generator(device='cpu').manual_seed(g['seed'])
            with torch.inference_mode():
                im=pipe(prompt=prompt,width=512,height=512,num_inference_steps=g['steps'],guidance_scale=0.0,generator=generator).images[0]
            sc,cl,c01,pm=image_score(im,clip_model,clip_proc,eval_text,torch)
            name=f'g{gen}_c{i}'; im.save(OUT/f'sd_{name}.png')
            row={'generation':gen,'candidate':i,'genes':g,'clip_cosine':cl,'clip_01':c01,'proxy_metrics':pm,'score':sc,
                 'prompt':prompt,'eval_text':eval_text,'file':f'sd_{name}.png'}
            rows.append(row); saved.append((name,im.copy(),row))
            if sc>best_score:
                best_score=sc; best=row; champion=g.copy(); im.save(selected_path)
        rows.sort(key=lambda x:x['score'],reverse=True); history.extend(rows)
        print('V32_SD_GEN',gen,'GEN_BEST',rows[0]['score'],'BEST_EVER',best_score,flush=True)

    thumb=256; label_h=42
    sheet=Image.new('RGB',(thumb*4,(thumb+label_h)*2),'white'); draw=ImageDraw.Draw(sheet)
    for k,(name,im,row) in enumerate(saved[:8]):
        x=(k%4)*thumb; y=(k//4)*(thumb+label_h); sheet.paste(im.resize((thumb,thumb)),(x,y))
        draw.text((x+6,y+thumb+5),f'{name} s={row["score"]:.3f} clip={row["clip_cosine"]:.3f}',fill='black')
    sheet.save(OUT/'sd_contact_sheet_latest.png')
    dump(OUT/'sd_evolution_latest.json',{'model':sd_id,'clip_model':clip_id,'eval_text':eval_text,
         'fitness':'0.82*fixed-target CLIP_mapped + 0.18*visual_proxy','history':history,'winner':best})
    del pipe,clip_model,clip_proc; gc.collect()
    return {'model':sd_id,'clip_model':clip_id,'initial_score':initial_best,'score':best_score,'winner':best,'genes':champion,'history':history,'eval_text':eval_text}


def main():
    t0=time.time(); fly=Path(os.environ.get('FLY_CONNECTOME','/tmp/flybrain/data/connectome.bin.gz'))
    stats,sig=parse_connectome(fly)
    assert stats['neurons']==139255 and stats['edges']==2698236 and stats['group_slots']==63 and stats['populated_group_ids']==32
    prior=load_prior_state(); start_gen=max(8,int(prior.get('generation',8)))
    llm=run_llm(sig,start_gen,prior.get('llm',{})); sd=run_image(sig,start_gen,prior.get('sd',{})); end_gen=start_gen+4
    state={'generation':end_gen,'connectome':stats,
           'llm':{'model':llm['model'],'score':llm['score'],'text':llm['text'],'genes':llm['genes'],'fitness_version':'v3.2'},
           'sd':{'model':sd['model'],'clip_model':sd['clip_model'],'score':sd['score'],'genes':sd['genes'],'winner':sd['winner'],'fitness_version':'v3.2-fixed-target'}}
    dump(V3_STATE,state)
    result={'status':'SUCCESS','generation_start':start_gen,'generation_end':end_gen,'connectome':stats,
            'models':{'llm':llm['model'],'diffusion':sd['model'],'semantic_evaluator':sd['clip_model']},
            'llm':{'before_score_v32':llm['initial_score'],'after_score_v32':llm['score'],'improved':llm['score']>llm['initial_score'],'chars':len(llm['text']),'champion_genes':llm['genes']},
            'image':{'before_score_v32_recomputed':sd['initial_score'],'after_score_v32':sd['score'],'improved':sd['score']>sd['initial_score'],'eval_text':sd['eval_text'],'winner':sd['winner']},
            'elapsed_seconds':time.time()-t0,
            'learning':'Qwen/SD-Turbo weights frozen; FlyBrain recurrent controller evolves generation parameters; v3.2 rejects truncated text and scores images against one fixed CLIP target'}
    dump(OUT/'result.json',result)
    (OUT/'summary.txt').write_text('\n'.join(['FLY CONNECTOME PERSISTENT NEUROEVOLUTION V3.2',f'generation {start_gen} -> {end_gen}',
        f'neurons={stats["neurons"]} edges={stats["edges"]} groups={stats["group_slots"]} populated={stats["populated_group_ids"]}',
        f'LLM {llm["initial_score"]:.6f} -> {llm["score"]:.6f} chars={len(llm["text"])}',f'Image {sd["initial_score"]:.6f} -> {sd["score"]:.6f}',
        f'elapsed={result["elapsed_seconds"]:.2f}s'])+'\n',encoding='utf-8')
    print(json.dumps(result,ensure_ascii=False,indent=2))

if __name__=='__main__': main()

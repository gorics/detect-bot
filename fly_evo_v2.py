#!/usr/bin/env python3
from __future__ import annotations
import gc, gzip, json, math, os, random, struct, time
from pathlib import Path
import numpy as np

OUT = Path('fly-evo-v2-results'); OUT.mkdir(exist_ok=True)
STATE = OUT / 'evolution_state.json'
SEED = 20260929
random.seed(SEED); np.random.seed(SEED)

def dump(name, obj):
    (OUT/name).write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding='utf-8')

def load_brain():
    raw=gzip.open('/tmp/flybrain/data/connectome.bin.gz','rb').read()
    N,E=struct.unpack_from('<II',raw,0)
    edge_dt=np.dtype([('pre','<u4'),('post','<u4'),('w','<f4')])
    meta_dt=np.dtype([('region','u1'),('group','<u2')])
    edges=np.frombuffer(raw,dtype=edge_dt,count=E,offset=8)
    meta=np.frombuffer(raw,dtype=meta_dt,count=N,offset=8+E*12)
    populated=int(meta['group'].max())+1
    G=max(63,populated)  # metadata schema has 63 slots; last slots may contain zero neurons
    pg=meta['group'][edges['pre']].astype(np.int64)
    qg=meta['group'][edges['post']].astype(np.int64)
    ew=edges['w'].astype(np.float64)
    cw=np.sign(ew)*np.log1p(np.abs(ew))
    W=np.bincount(pg*G+qg,weights=cw,minlength=G*G).reshape(G,G)
    den=np.sum(np.abs(W),axis=1,keepdims=True); den[den<1e-12]=1
    Wn=W/den
    sizes=np.bincount(meta['group'],minlength=G)
    greg=np.full(G,255,dtype=np.uint8)
    for g in range(G):
        ix=np.flatnonzero(meta['group']==g)
        if ix.size:
            v,c=np.unique(meta['region'][ix],return_counts=True); greg[g]=v[np.argmax(c)]
    a=np.zeros(G,dtype=np.float64); sens=np.flatnonzero(greg==0)
    if sens.size:
        z=np.sqrt(sizes[sens]+1.0); z/=max(1.,float(z.max())); a[sens]=.38+.62*z
    traj=[]
    for k in range(24):
        d=np.zeros(G); d[sens]=(.05+.02*math.sin(k*.87))*a[sens]
        a=np.tanh(.72*a+1.38*(a@Wn)+d); traj.append(a.copy())
    region_act=[float(np.mean(np.abs(a[greg==r]))) if np.any(greg==r) else 0. for r in range(4)]
    brain=np.array([a.mean(),a.std(),a.max(),a.min(),*region_act],dtype=np.float64)
    stats={'neurons':int(N),'edges':int(E),'group_slots':int(G),'populated_group_ids':int(populated),'region_counts':{str(r):int(np.sum(meta['region']==r)) for r in range(4)},'brain_signature':brain.tolist()}
    dump('connectome_stats.json',stats); np.savez_compressed(OUT/'connectome_controller.npz',W=W,Wn=Wn,trajectory=np.stack(traj),brain=brain)
    assert N==139255 and E==2698236
    return stats,brain

def tscore(s):
    keys=['초파리','connectome','LLM','Stable Diffusion','뉴런','보상','진화']
    cov=sum(k.lower() in s.lower() for k in keys)/len(keys)
    order=['입력','뇌활성','생성','평가','선택','돌연변이']; pos=[s.find(k) for k in order]
    ordscore=1.0 if all(p>=0 for p in pos) and pos==sorted(pos) else sum(p>=0 for p in pos)/len(pos)*.55
    n=len(s); length=max(0.,1-abs(n-360)/360)
    toks=[x for x in s.replace('\n',' ').split() if x]; uniq=len(set(zip(toks,toks[1:])))/max(1,len(toks)-1)
    replacement=1.0 if '\ufffd' not in s else 0.0
    return float(.45*cov+.20*ordscore+.12*length+.13*uniq+.10*replacement)

def run_llm(brain,state):
    import torch
    from transformers import AutoTokenizer,AutoModelForCausalLM
    torch.set_num_threads(max(1,min(4,os.cpu_count() or 2)))
    mid='Qwen/Qwen2.5-0.5B-Instruct'; tok=AutoTokenizer.from_pretrained(mid); model=AutoModelForCausalLM.from_pretrained(mid,torch_dtype=torch.float32,low_cpu_mem_usage=True); model.eval()
    prompt=tok.apply_chat_template([
      {'role':'system','content':'너는 connectome 기반 생성형 AI 연구 엔지니어다. 정확하고 간결한 한국어로만 답하고 깨진 문자를 출력하지 않는다.'},
      {'role':'user','content':'초파리 FlyWire connectome을 제어기·보상회로로 사용해 오픈소스 LLM과 Stable Diffusion을 결합한 진화형 AI 한 사이클을 6단계로 설명하라. 반드시 초파리, connectome, LLM, Stable Diffusion, 뉴런, 보상, 진화라는 단어를 포함하고, 단계는 정확히 입력 → 뇌활성 → 생성 → 평가 → 선택 → 돌연변이 순서로 쓴다.'}],tokenize=False,add_generation_prompt=True)
    inp=tok(prompt,return_tensors='pt')
    s=np.tanh(brain)
    default={'temperature':float(np.clip(.52+.25*abs(s[1]),.25,1.0)),'top_p':float(np.clip(.82+.10*abs(s[5]),.65,.97)),'rep':1.07,'max_new':150}
    champ=(state.get('llm') or {}).get('genes',default)
    best_score=float((state.get('llm') or {}).get('score',-1.0)); best_text=(state.get('llm') or {}).get('text','')
    start_gen=int(state.get('generation',0)); rng=np.random.default_rng(SEED+start_gen)
    hist=[]
    for local in range(4):
        gen=start_gen+local+1
        # Cached elite is never regenerated; phenotype cannot regress.
        rows=[]
        if best_score>=0: rows.append({'generation':gen,'candidate':'cached_elite','genes':champ,'score':best_score,'text':best_text,'elite':True})
        population=[]
        if best_score<0: population.append(champ.copy())
        for _ in range(3):
            population.append({'temperature':float(np.clip(champ['temperature']+rng.normal(0,.11),.22,1.10)),'top_p':float(np.clip(champ['top_p']+rng.normal(0,.04),.60,.99)),'rep':float(np.clip(champ['rep']+rng.normal(0,.025),1.0,1.18)),'max_new':int(np.clip(champ['max_new']+rng.normal(0,14),100,176))})
        for i,g in enumerate(population):
            torch.manual_seed(SEED+gen*100+i)
            with torch.inference_mode(): out=model.generate(**inp,do_sample=True,temperature=g['temperature'],top_p=g['top_p'],repetition_penalty=g['rep'],max_new_tokens=g['max_new'],pad_token_id=tok.eos_token_id)
            txt=tok.decode(out[0][inp['input_ids'].shape[1]:],skip_special_tokens=True).strip(); sc=tscore(txt)
            rows.append({'generation':gen,'candidate':i,'genes':g,'score':sc,'text':txt,'elite':False})
        rows.sort(key=lambda x:x['score'],reverse=True); hist.extend(rows)
        if rows[0]['score']>best_score:
            best_score=float(rows[0]['score']); best_text=rows[0]['text']; champ=rows[0]['genes']
        print('LLM_GEN',gen,'BEST_EVER',best_score)
    (OUT/'llm_evolved.txt').write_text(best_text+'\n',encoding='utf-8'); dump('llm_evolution.json',hist)
    state['llm']={'score':best_score,'text':best_text,'genes':champ,'model':mid}; state['generation']=start_gen+4
    del model,tok,inp; gc.collect()
    return mid,state

def imetrics(im):
    ar=np.asarray(im.convert('RGB'),dtype=np.float32)/255.; gray=ar.mean(2)
    h,_=np.histogram(gray,bins=64,range=(0,1)); p=h/h.sum(); p=p[p>0]
    ent=float(-(p*np.log2(p)).sum()/6); con=float(gray.std()); edge=float((np.abs(np.diff(gray,axis=0)).mean()+np.abs(np.diff(gray,axis=1)).mean())/2); sat=float(np.std(ar,axis=2).mean())
    sc=.30*min(1,ent)+.27*min(1,con/.24)+.27*min(1,edge/.12)+.16*min(1,sat/.2)
    return {'entropy':ent,'contrast':con,'edge':edge,'saturation':sat,'score':float(sc)}

def run_sd(brain,state):
    import torch
    from diffusers import DiffusionPipeline,DPMSolverMultistepScheduler
    from PIL import Image,ImageDraw
    torch.set_num_threads(max(1,min(4,os.cpu_count() or 2)))
    mid='segmind/tiny-sd'; pipe=DiffusionPipeline.from_pretrained(mid,torch_dtype=torch.float32); pipe.scheduler=DPMSolverMultistepScheduler.from_config(pipe.scheduler.config)
    if hasattr(pipe,'safety_checker'): pipe.safety_checker=None
    pipe.set_progress_bar_config(disable=True); pipe=pipe.to('cpu')
    prompt='macro photograph of a Drosophila fruit fly, transparent head revealing an intricate scientific neural connectome, glowing synapses, biological anatomy, dark laboratory background, sharp focus, high detail'
    neg='text, watermark, logo, extra wings, deformed insect, blurry, low detail'
    s=np.tanh(brain); default={'guidance':float(np.clip(6.0+1.3*abs(s[5])-.45*s[7],4.8,8.0)),'steps':6,'seed':SEED+int(abs(s[2])*10000)}
    prev=state.get('sd') or {}; genes=prev.get('genes',default); best_score=float(prev.get('score',-1)); best_metrics=prev.get('metrics'); best_seed=int(genes.get('seed',default['seed']))
    rng=np.random.default_rng(SEED+int(state['generation'])); records=[]; gallery=[]
    # If a previous champion exists, keep its score even if not regenerated.
    for gen in range(3):
        candidates=[]
        if best_score<0 and gen==0: candidates.append(dict(genes))
        for _ in range(2):
            candidates.append({'guidance':float(np.clip(genes['guidance']+rng.normal(0,.55),4.0,9.0)),'steps':int(np.clip(genes['steps']+rng.integers(-1,2),4,9)),'seed':int(rng.integers(1,2**31-1))})
        for i,g in enumerate(candidates):
            tg=torch.Generator(device='cpu').manual_seed(g['seed'])
            with torch.inference_mode(): im=pipe(prompt=prompt,negative_prompt=neg,width=256,height=256,num_inference_steps=g['steps'],guidance_scale=g['guidance'],generator=tg).images[0]
            m=imetrics(im); rec={'generation':gen+1,'candidate':i,'genes':g,'metrics':m}; records.append(rec); gallery.append((rec,im.copy()))
            if m['score']>best_score:
                best_score=m['score']; best_metrics=m; genes=g; best_seed=g['seed']; im.save(OUT/'sd_selected.png')
        print('SD_GEN',gen+1,'BEST_EVER',best_score)
    # best few generated candidates contact sheet
    top=sorted(gallery,key=lambda z:z[0]['metrics']['score'],reverse=True)[:4]
    sheet=Image.new('RGB',(512,560),'white'); draw=ImageDraw.Draw(sheet)
    for j,(rec,im) in enumerate(top):
        x=(j%2)*256; y=(j//2)*280; sheet.paste(im,(x,y)); draw.text((x+5,y+258),f"g{rec['generation']} score={rec['metrics']['score']:.3f}",fill='black')
    sheet.save(OUT/'sd_contact_sheet.png'); dump('sd_evolution.json',{'model':mid,'prompt':prompt,'records':records,'best_score':best_score,'best_genes':genes,'best_metrics':best_metrics})
    state['sd']={'score':best_score,'metrics':best_metrics,'genes':genes,'model':mid}; del pipe; gc.collect(); return mid,state

def main():
    t=time.time(); stats,brain=load_brain()
    state={}
    if STATE.exists():
        try: state=json.loads(STATE.read_text(encoding='utf-8'))
        except Exception: state={}
    before={'generation':int(state.get('generation',0)),'llm_score':float((state.get('llm') or {}).get('score',-1)),'sd_score':float((state.get('sd') or {}).get('score',-1))}
    llm,state=run_llm(brain,state); sd,state=run_sd(brain,state); dump('evolution_state.json',state)
    result={'status':'SUCCESS','connectome':stats,'before':before,'after':{'generation':state['generation'],'llm_score':state['llm']['score'],'sd_score':state['sd']['score']},'llm_model':llm,'stable_diffusion_model':sd,'llm_champion_genes':state['llm']['genes'],'sd_champion_genes':state['sd']['genes'],'elapsed_seconds':time.time()-t,'learning':'base LLM/SD weights frozen; connectome-conditioned controller evolves with strict best-ever elitism; state persists across runs'}
    dump('result.json',result); (OUT/'summary.txt').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8'); print(json.dumps(result,ensure_ascii=False,indent=2))
if __name__=='__main__': main()

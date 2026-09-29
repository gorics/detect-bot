#!/usr/bin/env python3
import argparse, gzip, json, os, random, struct, time
from pathlib import Path

import numpy as np
import torch

SEED = 20260929
random.seed(SEED); np.random.seed(SEED); torch.manual_seed(SEED)

STIMULI = {
    "food":  {"groups":[6,32,37], "behavior":"approach food and extend the proboscis to feed"},
    "touch": {"groups":[10,35],   "behavior":"orient away from touch and initiate grooming"},
    "air":   {"groups":[11,5,35], "behavior":"brace against airflow and prepare an escape response"},
    "light": {"groups":[0,2,25],  "behavior":"orient toward the bright visual field and explore"},
    "warm":  {"groups":[14,35],   "behavior":"move away from the warm region while exploring"},
    "cool":  {"groups":[15,35],   "behavior":"reorient after cooling and reduce forward exploration"},
}
KINDS = list(STIMULI)


def load_connectome(path: Path):
    with gzip.open(path, "rb") as f:
        raw = f.read()
    n, e = struct.unpack_from("<II", raw, 0)
    dt = np.dtype([("pre","<u4"),("post","<u4"),("w","<f4")])
    edges = np.frombuffer(raw, dtype=dt, count=e, offset=8)
    off = 8 + e * 12
    meta = np.frombuffer(raw, dtype=np.uint8, count=n*3, offset=off).reshape(n,3)
    groups = meta[:,1].astype(np.uint16) + (meta[:,2].astype(np.uint16) << 8)
    m = max(float(np.max(np.abs(edges["w"]))), 1e-8)
    w = edges["w"].astype(np.float32) / m * 0.15
    pre_g = groups[edges["pre"]].astype(np.int64)
    post_g = groups[edges["post"]].astype(np.int64)
    flat = pre_g * 63 + post_g
    W = np.bincount(flat, weights=w, minlength=63*63).reshape(63,63).astype(np.float32)
    Wn = W / np.maximum(np.sum(np.abs(W), axis=1, keepdims=True), 1e-6)
    counts = np.bincount(groups, minlength=63).astype(np.int64)
    return n, e, W, Wn, counts


def simulate(Wn, kind, intensity=1.0, noise=0.02, steps=14, seed=SEED):
    stim = np.zeros(63, np.float32)
    for g in STIMULI[kind]["groups"]: stim[g] = intensity
    x = np.zeros(63, np.float32)
    rng = np.random.default_rng(seed)
    for t in range(steps):
        pulse = 1.0 if t < 4 else 0.30
        x = np.tanh(1.70*(Wn.T @ x) + pulse*stim + rng.normal(0,noise,63).astype(np.float32))
    return x.astype(np.float32)


def dataset(Wn, per_class=100):
    X=[]; y=[]
    rng=np.random.default_rng(SEED+33)
    for k_idx,k in enumerate(KINDS):
        for j in range(per_class):
            X.append(simulate(Wn,k,float(rng.uniform(.52,1.38)),float(rng.uniform(.008,.05)),int(rng.integers(9,19)),SEED+k_idx*10000+j))
            y.append(k_idx)
    X=np.stack(X); y=np.asarray(y,np.int64)
    p=rng.permutation(len(y)); return X[p],y[p]


def accuracy(popW, popB, X, y):
    # popW: [P,C,D], X: [N,D]
    logits=np.einsum("pcd,nd->pnc",popW,X,optimize=True)+popB[:,None,:]
    pred=logits.argmax(2)
    return (pred==y[None,:]).mean(1)


def evolve(Wn, out: Path, generations=120, population=96):
    X,y=dataset(Wn)
    split=int(len(y)*.82)
    xt,yt=X[:split],y[:split]; xv,yv=X[split:],y[split:]
    rng=np.random.default_rng(SEED+101)
    popW=rng.normal(0,.18,(population,len(KINDS),63)).astype(np.float32)
    popB=rng.normal(0,.03,(population,len(KINDS))).astype(np.float32)
    state_dir=out/"state"; state_dir.mkdir(parents=True,exist_ok=True)
    state_path=state_dir/"best_genome.npz"
    resumed=False
    if state_path.exists():
        old=np.load(state_path)
        if old["W"].shape==(len(KINDS),63):
            popW[0]=old["W"].astype(np.float32); popB[0]=old["B"].astype(np.float32); resumed=True
    hist=[]; bestW=None; bestB=None; best_val=-1.0
    baseline=float(accuracy(popW,popB,xv,yv).max())
    elite_n=max(8,population//8)
    for gen in range(generations):
        train_acc=accuracy(popW,popB,xt,yt)
        # fitness rewards accuracy and discourages huge weights
        reg=np.mean(popW*popW,axis=(1,2))
        fit=train_acc-1e-4*reg
        order=np.argsort(fit)[::-1]
        elitesW=popW[order[:elite_n]].copy(); elitesB=popB[order[:elite_n]].copy()
        val_acc=accuracy(elitesW,elitesB,xv,yv)
        j=int(np.argmax(val_acc))
        if float(val_acc[j])>=best_val:
            best_val=float(val_acc[j]); bestW=elitesW[j].copy(); bestB=elitesB[j].copy()
        hist.append({"generation":gen,"train_best":float(train_acc[order[0]]),"validation_best":float(val_acc[j]),"fitness_best":float(fit[order[0]])})
        # elitism + tournament-like parent sampling + annealed Gaussian mutation
        sigma=.20*(1-gen/max(generations,1))+.018
        newW=[w.copy() for w in elitesW]; newB=[b.copy() for b in elitesB]
        while len(newW)<population:
            pidx=int(rng.integers(0,elite_n)); qidx=int(rng.integers(0,elite_n))
            mask=rng.random((len(KINDS),63))<.5
            childW=np.where(mask,elitesW[pidx],elitesW[qidx])
            childB=(elitesB[pidx]+elitesB[qidx])*.5
            childW=childW+rng.normal(0,sigma,childW.shape).astype(np.float32)
            childB=childB+rng.normal(0,sigma*.25,childB.shape).astype(np.float32)
            newW.append(childW.astype(np.float32)); newB.append(childB.astype(np.float32))
        popW=np.stack(newW[:population]); popB=np.stack(newB[:population])
    np.savez_compressed(state_path,W=bestW,B=bestB,validation_accuracy=np.float32(best_val),generations=np.int32(generations))
    (out/"evolution_history.json").write_text(json.dumps(hist,indent=2),encoding="utf-8")
    return bestW,bestB,best_val,baseline,resumed,hist


def predict(W,B,state):
    logits=W@state+B
    z=logits-logits.max(); p=np.exp(z); p=p/p.sum()
    i=int(p.argmax())
    return KINDS[i],{k:float(p[j]) for j,k in enumerate(KINDS)}


def run_llm(predicted,state,probs,out):
    from transformers import AutoTokenizer, AutoModelForCausalLM
    model_id=os.getenv("FLY_LLM","HuggingFaceTB/SmolLM2-135M-Instruct")
    tok=AutoTokenizer.from_pretrained(model_id)
    model=AutoModelForCausalLM.from_pretrained(model_id,torch_dtype=torch.float32)
    model.eval()
    top=np.argsort(np.abs(state))[-10:][::-1]
    summary=", ".join(f"g{int(i)}={state[i]:+.2f}" for i in top)
    messages=[
      {"role":"system","content":"You decode a simulated Drosophila connectome state. Be concise and do not claim consciousness."},
      {"role":"user","content":f"Evolved readout predicts {predicted}. Neural groups: {summary}. Probabilities: {json.dumps(probs)}. State the likely next behavior in one factual sentence."}
    ]
    if getattr(tok,"chat_template",None): text=tok.apply_chat_template(messages,tokenize=False,add_generation_prompt=True)
    else: text="System: "+messages[0]["content"]+"\nUser: "+messages[1]["content"]+"\nAssistant:"
    inp=tok(text,return_tensors="pt")
    with torch.inference_mode():
        ids=model.generate(**inp,max_new_tokens=64,do_sample=False,repetition_penalty=1.05,pad_token_id=tok.eos_token_id)
    s=tok.decode(ids[0][inp["input_ids"].shape[1]:],skip_special_tokens=True).strip()
    (out/"llm_output.txt").write_text(s+"\n",encoding="utf-8")
    del model
    return model_id,s


def run_sd(predicted,out):
    from diffusers import StableDiffusionPipeline, DPMSolverMultistepScheduler
    model_id=os.getenv("FLY_SD","segmind/tiny-sd")
    pipe=StableDiffusionPipeline.from_pretrained(model_id,torch_dtype=torch.float32,safety_checker=None,requires_safety_checker=False)
    try: pipe.scheduler=DPMSolverMultistepScheduler.from_config(pipe.scheduler.config)
    except Exception: pass
    pipe=pipe.to("cpu")
    try: pipe.enable_attention_slicing()
    except Exception: pass
    behavior=STIMULI[predicted]["behavior"]
    prompt=("scientific macro photograph of Drosophila melanogaster in a neural laboratory, "
            f"fruit fly behavior: {behavior}, visible glowing connectome pathways, microscopy, realistic anatomy, high detail")
    neg="text, watermark, malformed insect, duplicate wings, blurry"
    g=torch.Generator(device="cpu").manual_seed(SEED)
    t=time.time()
    image=pipe(prompt=prompt,negative_prompt=neg,num_inference_steps=6,guidance_scale=6.0,height=256,width=256,generator=g).images[0]
    sec=time.time()-t
    image.save(out/"stable_diffusion_result.png")
    image.resize((512,512)).save(out/"stable_diffusion_result_512.png")
    return model_id,prompt,float(sec)


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--flybrain",type=Path,required=True)
    ap.add_argument("--out",type=Path,default=Path("results"))
    ap.add_argument("--generations",type=int,default=120)
    ap.add_argument("--population",type=int,default=96)
    ap.add_argument("--stimulus",choices=KINDS,default="food")
    a=ap.parse_args(); a.out.mkdir(parents=True,exist_ok=True)
    t0=time.time()
    meta=json.loads((a.flybrain/"data/neuron_meta.json").read_text())
    names=[g["name"] for g in meta["groups"]]
    n,e,W,Wn,counts=load_connectome(a.flybrain/"data/connectome.bin.gz")
    np.save(a.out/"group_connectome.npy",W)
    bestW,bestB,val,baseline,resumed,hist=evolve(Wn,a.out,a.generations,a.population)
    state=simulate(Wn,a.stimulus,1.05,.012,15,SEED+999)
    pred,probs=predict(bestW,bestB,state)
    top=np.argsort(np.abs(state))[-12:][::-1]
    top_groups=[{"id":int(i),"name":names[int(i)] if int(i)<len(names) else str(i),"activation":float(state[i]),"neurons":int(counts[i])} for i in top]
    llm_id,llm_text=run_llm(pred,state,probs,a.out)
    sd_id,sd_prompt,sd_sec=run_sd(pred,a.out)
    result={
      "seed":SEED,
      "connectome":{"neurons":int(n),"edges":int(e),"groups":63,"nonzero_group_edges":int(np.count_nonzero(W))},
      "evolution":{"generations":a.generations,"population":a.population,"resumed_checkpoint":resumed,"initial_random_best_validation_accuracy":baseline,"final_best_validation_accuracy":val,"first":hist[0],"last":hist[-1]},
      "demo":{"requested_stimulus":a.stimulus,"evolved_prediction":pred,"probabilities":probs,"top_groups":top_groups},
      "llm":{"model":llm_id,"output":llm_text},
      "stable_diffusion":{"model":sd_id,"prompt":sd_prompt,"inference_seconds":sd_sec,"image":"stable_diffusion_result.png"},
      "training_scope":{"trained":"connectome-to-semantic evolutionary readout/controller","frozen_base_models":[llm_id,sd_id]},
      "total_seconds":float(time.time()-t0)
    }
    (a.out/"results.json").write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding="utf-8")
    print(json.dumps(result,ensure_ascii=False,indent=2))

if __name__=="__main__": main()

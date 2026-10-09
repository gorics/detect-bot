#!/usr/bin/env python3
"""Independent within-run audits for FlyBrain champion promotion.

Readout: synthetic neural states not used in evolution's candidate-selection set.
SmolLM2: fresh held-out neural prompts not used in LoRA training. These are
simulation-based tests, NOT evidence of actual fly thoughts or neural recordings.
"""
import argparse
import json
import os
from pathlib import Path
import numpy as np


def independent_seed():
    return 73109031 + int(os.getenv("GITHUB_RUN_ID", "0")) * 17 + int(os.getenv("GITHUB_RUN_ATTEMPT", "1"))


def readout_audit(args):
    from flybrain_ai_evolution import SEED, KINDS, simulate, accuracy, heldout_nll
    W=np.load(args.group_matrix,allow_pickle=False)
    if W.shape!=(63,63): raise RuntimeError("Wrong connectome group matrix")
    Wn=W/np.maximum(np.sum(np.abs(W),axis=1,keepdims=True),1e-6)
    seed=independent_seed()
    rng=np.random.default_rng(seed)
    xs=[]; ys=[]
    for k,kind in enumerate(KINDS):
        for j in range(40):
            xs.append(simulate(Wn,kind,float(rng.uniform(.52,1.38)),
                float(rng.uniform(.008,.05)),int(rng.integers(9,19)),
                seed+100000+k*1000+j))
            ys.append(k)
    X=np.stack(xs); y=np.asarray(ys,dtype=np.int64)
    before=np.load(args.incumbent,allow_pickle=False)
    after=np.load(args.candidate,allow_pickle=False)
    def scores(z):
        w=z["W"].astype(np.float32); b=z["B"].astype(np.float32)
        if w.shape!=(6,63) or b.shape!=(6,): raise RuntimeError("Readout checkpoint shape mismatch")
        return float(accuracy(w[None],b[None],X,y)[0]),heldout_nll(w,b,X,y)
    a0,n0=scores(before); a1,n1=scores(after)
    # Strict no accuracy loss; meaningful NLL decrease, with an absolute floor.
    improved=(a1>=a0-1e-12 and n1<n0-1e-5 and
              (n0-n1)/max(n0,1e-12)>0.005)
    result={"kind":"synthetic_independent_audit","seed":seed,"samples":len(y),
            "incumbent_accuracy":a0,"candidate_accuracy":a1,
            "incumbent_nll":n0,"candidate_nll":n1,
            "champion_promoted":bool(improved),
            "gate":"accuracy nondecrease, NLL reduction > 0.5% and > 1e-5"}
    args.output.write_text(json.dumps(result,indent=2),encoding="utf-8")
    print(json.dumps(result,indent=2))
    return improved


def llm_audit(args):
    import torch
    from transformers import AutoTokenizer,AutoModelForCausalLM
    from peft import PeftModel
    from flybrain_direct_lora import build_lm_examples,load_connectome,load_evolved_readout
    if not args.flybrain: raise RuntimeError("--flybrain required")
    if not args.readout: raise RuntimeError("--readout required")
    _,_,Wn=load_connectome(args.flybrain/"data/connectome.bin.gz")
    W,B,_=load_evolved_readout(args.readout)
    # Completely different RNG seeds from the training examples and the fixed
    # six held-out examples. This audit set changes each generation.
    seed=independent_seed()
    rows=build_lm_examples(Wn,W,B,per_kind=2,seed_offset=1_000_000+seed%100_000_000)
    model_id="HuggingFaceTB/SmolLM2-135M-Instruct"
    tok=AutoTokenizer.from_pretrained(model_id)
    if tok.pad_token_id is None: tok.pad_token=tok.eos_token
    def formatted(row):
        msgs=[{"role":"system","content":"You decode simulated fruit-fly neural states. Do not claim consciousness."},
              {"role":"user","content":row["prompt"]}]
        if getattr(tok,"chat_template",None):
            return tok.apply_chat_template(msgs,tokenize=False,add_generation_prompt=True)
        return f"System: {msgs[0]['content']}\nUser: {msgs[1]['content']}\nAssistant:"
    def measure(adapter):
        base=AutoModelForCausalLM.from_pretrained(model_id,torch_dtype=torch.float32)
        model=PeftModel.from_pretrained(base,adapter,is_trainable=False)
        model.eval(); losses=[]; correct=0
        with torch.inference_mode():
            for row in rows:
                prompt=formatted(row)
                enc=tok(prompt+row["target"]+tok.eos_token,return_tensors="pt",truncation=True,max_length=256)
                plen=tok(prompt,return_tensors="pt",truncation=True,max_length=256)["input_ids"].shape[1]
                labels=enc["input_ids"].clone()
                labels[:,:min(plen,labels.shape[1])]=-100
                if not (labels!=-100).any(): raise RuntimeError("Audit target was truncated")
                losses.append(float(model(**enc,labels=labels).loss))
                prompt_inputs=tok(prompt,return_tensors="pt",truncation=True,max_length=256)
                generated=model.generate(**prompt_inputs,max_new_tokens=36,do_sample=False,
                                         pad_token_id=tok.eos_token_id)
                answer=tok.decode(generated[0][prompt_inputs["input_ids"].shape[1]:],
                                  skip_special_tokens=True).strip()
                correct+=int(row["target"].lower() in answer.lower())
        del model,base
        return correct/len(rows),float(np.mean(losses))
    a0,n0=measure(args.incumbent)
    a1,n1=measure(args.candidate)
    # Avoid promotion on floating-point rounding of already near-zero NLL.
    improved=(a1>=a0-1e-12 and n1<n0-1e-8 and (n0-n1)/max(n0,1e-12)>0.02)
    result={"kind":"fresh_synthetic_neural_prompt_holdout","seed":seed,
            "samples":len(rows),"incumbent_accuracy":a0,"candidate_accuracy":a1,
            "incumbent_nll":n0,"candidate_nll":n1,"champion_promoted":bool(improved),
            "gate":"accuracy nondecrease, NLL reduction > 2% and > 1e-8"}
    args.output.write_text(json.dumps(result,indent=2),encoding="utf-8")
    print(json.dumps(result,indent=2))
    return improved


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--mode",choices=["readout","llm"],required=True)
    p.add_argument("--incumbent",type=Path,required=True)
    p.add_argument("--candidate",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--group-matrix",type=Path)
    p.add_argument("--flybrain",type=Path)
    p.add_argument("--readout",type=Path)
    a=p.parse_args()
    a.output.parent.mkdir(parents=True,exist_ok=True)
    if a.mode=="readout":
        if not a.group_matrix: p.error("--group-matrix required for readout")
        readout_audit(a)
    else: llm_audit(a)

if __name__=="__main__": main()

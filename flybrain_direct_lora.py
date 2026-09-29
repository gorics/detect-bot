#!/usr/bin/env python3
import argparse, gc, gzip, json, os, random, struct, time
from pathlib import Path

import numpy as np
import torch
import torch.nn.functional as F

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
KINDS=list(STIMULI)


def load_connectome(path: Path):
    with gzip.open(path,"rb") as f: raw=f.read()
    n,e=struct.unpack_from("<II",raw,0)
    dt=np.dtype([("pre","<u4"),("post","<u4"),("w","<f4")])
    edges=np.frombuffer(raw,dtype=dt,count=e,offset=8)
    off=8+e*12
    meta=np.frombuffer(raw,dtype=np.uint8,count=n*3,offset=off).reshape(n,3)
    groups=meta[:,1].astype(np.uint16)+(meta[:,2].astype(np.uint16)<<8)
    m=max(float(np.max(np.abs(edges["w"]))),1e-8)
    w=edges["w"].astype(np.float32)/m*.15
    flat=groups[edges["pre"]].astype(np.int64)*63+groups[edges["post"]].astype(np.int64)
    W=np.bincount(flat,weights=w,minlength=63*63).reshape(63,63).astype(np.float32)
    Wn=W/np.maximum(np.sum(np.abs(W),axis=1,keepdims=True),1e-6)
    return n,e,Wn


def simulate(Wn,kind,intensity=1.0,noise=.02,steps=14,seed=SEED):
    stim=np.zeros(63,np.float32)
    for g in STIMULI[kind]["groups"]: stim[g]=intensity
    x=np.zeros(63,np.float32); rng=np.random.default_rng(seed)
    for t in range(steps):
        pulse=1.0 if t<4 else .30
        x=np.tanh(1.70*(Wn.T@x)+pulse*stim+rng.normal(0,noise,63).astype(np.float32))
    return x


def load_evolved_readout(path: Path):
    d=np.load(path)
    return d["W"].astype(np.float32),d["B"].astype(np.float32),float(d["validation_accuracy"])


def readout(W,B,state):
    z=W@state+B; z=z-z.max(); p=np.exp(z); p/=p.sum(); i=int(p.argmax())
    return KINDS[i],p


def state_summary(state,k=10):
    top=np.argsort(np.abs(state))[-k:][::-1]
    return ", ".join(f"g{int(i)}={state[i]:+.2f}" for i in top)


def build_lm_examples(Wn,W,B,per_kind=5,seed_offset=400):
    rng=np.random.default_rng(SEED+seed_offset)
    rows=[]
    for ki,kind in enumerate(KINDS):
        for j in range(per_kind):
            s=simulate(Wn,kind,float(rng.uniform(.62,1.28)),float(rng.uniform(.008,.040)),int(rng.integers(10,19)),SEED+seed_offset*10+ki*100+j)
            pred,p=readout(W,B,s)
            prompt=("Decode this simulated Drosophila connectome state into the next behavior. "
                    f"Evolved controller class={pred}. neural_state={state_summary(s)}. "
                    "Answer with one short behavior sentence.")
            rows.append({"kind":kind,"prompt":prompt,"target":STIMULI[kind]["behavior"]})
    random.Random(SEED+seed_offset).shuffle(rows)
    return rows


def train_llm_lora(train_rows,holdout_rows,out: Path):
    from transformers import AutoTokenizer, AutoModelForCausalLM
    from peft import LoraConfig, TaskType, PeftModel, get_peft_model

    model_id=os.getenv("FLY_LLM","HuggingFaceTB/SmolLM2-135M-Instruct")
    tok=AutoTokenizer.from_pretrained(model_id)
    if tok.pad_token_id is None: tok.pad_token=tok.eos_token
    base=AutoModelForCausalLM.from_pretrained(model_id,torch_dtype=torch.float32)
    lora_dir=out/"llm_lora"
    resumed=(lora_dir/"adapter_model.safetensors").exists()
    if resumed:
        model=PeftModel.from_pretrained(base,lora_dir,is_trainable=True)
        lr=2e-4; epochs=1
    else:
        cfg=LoraConfig(task_type=TaskType.CAUSAL_LM,r=8,lora_alpha=16,lora_dropout=.05,
                       target_modules=["q_proj","k_proj","v_proj","o_proj"],bias="none")
        model=get_peft_model(base,cfg); lr=8e-4; epochs=3

    def format_prompt(r):
        msgs=[{"role":"system","content":"You decode simulated fruit-fly neural states. Do not claim consciousness."},
              {"role":"user","content":r["prompt"]}]
        if getattr(tok,"chat_template",None): return tok.apply_chat_template(msgs,tokenize=False,add_generation_prompt=True)
        return f"System: {msgs[0]['content']}\nUser: {msgs[1]['content']}\nAssistant:"

    def generate(r):
        model.eval(); text=format_prompt(r); inp=tok(text,return_tensors="pt",truncation=True,max_length=256)
        with torch.inference_mode(): ids=model.generate(**inp,max_new_tokens=36,do_sample=False,pad_token_id=tok.eos_token_id)
        return tok.decode(ids[0][inp["input_ids"].shape[1]:],skip_special_tokens=True).strip()

    def score(rows):
        outs=[]; hit=0
        for r in rows:
            s=generate(r); outs.append({"kind":r["kind"],"target":r["target"],"output":s})
            if r["target"].lower() in s.lower(): hit+=1
        return hit/len(rows),outs

    acc_before,out_before=score(holdout_rows)
    model.train(); trainable=sum(p.numel() for p in model.parameters() if p.requires_grad); total=sum(p.numel() for p in model.parameters())
    params=[p for p in model.parameters() if p.requires_grad]
    opt=torch.optim.AdamW(params,lr=lr,weight_decay=1e-4); losses=[]
    for epoch in range(epochs):
        random.Random(SEED+900+epoch).shuffle(train_rows)
        for r in train_rows:
            prompt=format_prompt(r); full=prompt+r["target"]+tok.eos_token
            enc=tok(full,return_tensors="pt",truncation=True,max_length=256)
            plen=tok(prompt,return_tensors="pt",truncation=True,max_length=256)["input_ids"].shape[1]
            labels=enc["input_ids"].clone(); labels[:,:min(plen,labels.shape[1])]=-100
            loss=model(**enc,labels=labels).loss
            opt.zero_grad(); loss.backward(); torch.nn.utils.clip_grad_norm_(params,1.0); opt.step(); losses.append(float(loss.detach()))
    acc_after,out_after=score(holdout_rows)
    lora_dir.mkdir(parents=True,exist_ok=True); model.save_pretrained(lora_dir)
    (out/"llm_holdout_before.json").write_text(json.dumps(out_before,ensure_ascii=False,indent=2),encoding="utf-8")
    (out/"llm_holdout_after.json").write_text(json.dumps(out_after,ensure_ascii=False,indent=2),encoding="utf-8")
    del model,base; gc.collect()
    return {"model":model_id,"resumed_adapter":resumed,"trainable_parameters":trainable,"total_parameters":total,
            "trainable_fraction":trainable/total,"steps":len(losses),"learning_rate":lr,"loss_first":losses[0],"loss_last":losses[-1],
            "loss_mean_first5":float(np.mean(losses[:5])),"loss_mean_last5":float(np.mean(losses[-5:])),
            "holdout_accuracy_before":acc_before,"holdout_accuracy_after":acc_after}


def sd_prompt(kind):
    return (f"macro scientific photograph of a single fruit fly, Drosophila melanogaster, {STIMULI[kind]['behavior']}, "
            "red compound eyes, two transparent wings, six legs, realistic insect anatomy, natural light, sharp focus")


def train_sd_lora(out: Path,steps=36):
    from diffusers import StableDiffusionPipeline, DDPMScheduler
    from peft import LoraConfig
    from torchvision.transforms.functional import to_tensor

    model_id=os.getenv("FLY_SD_TRAIN","segmind/tiny-sd")
    pipe=StableDiffusionPipeline.from_pretrained(model_id,torch_dtype=torch.float32,safety_checker=None,requires_safety_checker=False).to("cpu")
    pipe.set_progress_bar_config(disable=True)
    try: pipe.enable_attention_slicing()
    except Exception: pass

    # Keep the same teacher set across generations so validation is comparable.
    teacher_dir=out/"sd_teacher"; teacher_dir.mkdir(parents=True,exist_ok=True)
    teacher=[]
    missing=any(not (teacher_dir/f"{k}.png").exists() for k in KINDS)
    if missing:
        g=torch.Generator(device="cpu").manual_seed(SEED+77)
        with torch.inference_mode():
            for kind in KINDS:
                im=pipe(sd_prompt(kind),num_inference_steps=5,guidance_scale=5.0,height=128,width=128,generator=g).images[0]
                im.save(teacher_dir/f"{kind}.png")
    from PIL import Image
    for kind in KINDS: teacher.append((kind,Image.open(teacher_dir/f"{kind}.png").convert("RGB")))

    # Base image with the same seed for visual A/B comparison.
    g0=torch.Generator(device="cpu").manual_seed(SEED+909)
    with torch.inference_mode():
        pipe(sd_prompt("food"),num_inference_steps=8,guidance_scale=6.0,height=256,width=256,generator=g0).images[0].save(out/"sd_base_result.png")

    pipe.vae.requires_grad_(False); pipe.text_encoder.requires_grad_(False); pipe.unet.requires_grad_(False)
    cfg=LoraConfig(r=4,lora_alpha=4,lora_dropout=0.0,bias="none",target_modules=["to_q","to_k","to_v","to_out.0"])
    pipe.unet.add_adapter(cfg)
    resume_path=out/"sd_unet_lora.pt"; resumed=resume_path.exists()
    if resumed:
        old=torch.load(resume_path,map_location="cpu"); pipe.unet.load_state_dict(old["state_dict"],strict=False)
    params=[p for p in pipe.unet.parameters() if p.requires_grad]
    ntrain=sum(p.numel() for p in params); ntotal=sum(p.numel() for p in pipe.unet.parameters())
    opt=torch.optim.AdamW(params,lr=3e-5 if resumed else 8e-5,weight_decay=1e-4)
    scheduler=DDPMScheduler.from_config(pipe.scheduler.config)

    # Deterministic denoising validation cases: fixed image, latent mean, noise and timestep.
    cases=[]
    for i,(kind,im) in enumerate(teacher):
        pix=to_tensor(im).unsqueeze(0)*2-1
        with torch.no_grad():
            lat=pipe.vae.encode(pix).latent_dist.mean*pipe.vae.config.scaling_factor
            toks=pipe.tokenizer(sd_prompt(kind),padding="max_length",max_length=pipe.tokenizer.model_max_length,truncation=True,return_tensors="pt")
            hidden=pipe.text_encoder(toks.input_ids)[0]
        gen=torch.Generator(device="cpu").manual_seed(SEED+1200+i)
        noise=torch.randn(lat.shape,generator=gen,dtype=lat.dtype)
        t=torch.tensor([120+110*i],dtype=torch.long)
        noisy=scheduler.add_noise(lat,noise,t)
        target=noise if scheduler.config.prediction_type=="epsilon" else scheduler.get_velocity(lat,noise,t)
        cases.append((kind,noisy,t,hidden,target))

    def eval_loss():
        pipe.unet.eval(); vals=[]
        with torch.no_grad():
            for _,noisy,t,hidden,target in cases:
                pred=pipe.unet(noisy,t,encoder_hidden_states=hidden).sample
                vals.append(float(F.mse_loss(pred.float(),target.float())))
        return float(np.mean(vals)),vals

    val_before,per_before=eval_loss(); losses=[]; pipe.unet.train()
    for step in range(steps):
        _,noisy,t,hidden,target=cases[step%len(cases)]
        pred=pipe.unet(noisy,t,encoder_hidden_states=hidden).sample
        loss=F.mse_loss(pred.float(),target.float())
        opt.zero_grad(); loss.backward(); torch.nn.utils.clip_grad_norm_(params,1.0); opt.step(); losses.append(float(loss.detach()))
    val_after,per_after=eval_loss()
    lora_state={k:v.detach().cpu() for k,v in pipe.unet.state_dict().items() if "lora_" in k}
    delta_norm=float(sum(v.float().norm().item() for v in lora_state.values()))
    torch.save({"config":{"r":4,"alpha":4,"targets":["to_q","to_k","to_v","to_out.0"]},"state_dict":lora_state,"validation_loss":val_after},resume_path)
    g1=torch.Generator(device="cpu").manual_seed(SEED+909); t0=time.time(); pipe.unet.eval()
    with torch.inference_mode():
        image=pipe(sd_prompt("food"),num_inference_steps=10,guidance_scale=6.0,height=256,width=256,generator=g1).images[0]
    infer=time.time()-t0; image.save(out/"sd_lora_result.png")
    (out/"sd_validation.json").write_text(json.dumps({"before":per_before,"after":per_after},indent=2),encoding="utf-8")
    del pipe; gc.collect()
    return {"model":model_id,"resumed_adapter":resumed,"trainable_parameters":ntrain,"total_unet_parameters":ntotal,
            "trainable_fraction":ntrain/ntotal,"steps":steps,"learning_rate":opt.param_groups[0]["lr"],
            "fixed_validation_loss_before":val_before,"fixed_validation_loss_after":val_after,
            "validation_improvement_fraction":(val_before-val_after)/max(val_before,1e-12),
            "train_loss_first":losses[0],"train_loss_last":losses[-1],"lora_weight_norm_sum":delta_norm,
            "inference_seconds":infer,"base_output":"sd_base_result.png","lora_output":"sd_lora_result.png"}


def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--flybrain",type=Path,required=True); ap.add_argument("--out",type=Path,default=Path("lora_results")); ap.add_argument("--sd-steps",type=int,default=36)
    a=ap.parse_args(); a.out.mkdir(parents=True,exist_ok=True); t0=time.time()
    n,e,Wn=load_connectome(a.flybrain/"data/connectome.bin.gz")
    W,B,val=load_evolved_readout(Path("results/state/best_genome.npz"))
    train_rows=build_lm_examples(Wn,W,B,per_kind=5,seed_offset=400)
    holdout=build_lm_examples(Wn,W,B,per_kind=1,seed_offset=777)
    (a.out/"training_examples.json").write_text(json.dumps(train_rows,ensure_ascii=False,indent=2),encoding="utf-8")
    llm=train_llm_lora(train_rows,holdout,a.out)
    sd=train_sd_lora(a.out,a.sd_steps)
    result={"seed":SEED,"generation_mode":"resume adapters if present","connectome":{"neurons":n,"edges":e},
            "evolved_checkpoint_validation_accuracy":val,"llm_lora":llm,"stable_diffusion_lora":sd,"total_seconds":time.time()-t0,
            "scope":"Frozen base models + trainable LoRA adapters; existing adapters and the evolved FlyBrain readout are reused across generations."}
    (a.out/"lora_results.json").write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding="utf-8")
    print(json.dumps(result,ensure_ascii=False,indent=2))

if __name__=="__main__": main()

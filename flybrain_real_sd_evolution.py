#!/usr/bin/env python3
import argparse, gc, json, math, os, shutil, time
from pathlib import Path

import numpy as np
import torch
import torch.nn.functional as F
from PIL import Image, ImageOps, ImageEnhance

SEED=20260929
torch.manual_seed(SEED); np.random.seed(SEED)
PROMPT="scientific macro photograph of Drosophila melanogaster, fruit fly, red compound eyes, transparent wings, six legs, realistic insect anatomy, specimen photography"
TARGETS=["to_q","to_k","to_v","to_out.0"]


def prep_image(path,size=128,augment=False,seed=0):
    im=Image.open(path).convert("RGB")
    w,h=im.size; side=max(w,h); canvas=Image.new("RGB",(side,side),(245,245,245)); canvas.paste(im,((side-w)//2,(side-h)//2))
    im=canvas.resize((size,size),Image.Resampling.LANCZOS)
    if augment:
        rng=np.random.default_rng(seed)
        if rng.random()<.5: im=ImageOps.mirror(im)
        im=ImageEnhance.Brightness(im).enhance(float(rng.uniform(.90,1.10)))
        im=ImageEnhance.Contrast(im).enhance(float(rng.uniform(.92,1.08)))
    return im


def make_pipe(model_id):
    from diffusers import StableDiffusionPipeline
    p=StableDiffusionPipeline.from_pretrained(model_id,torch_dtype=torch.float32,safety_checker=None,requires_safety_checker=False).to("cpu")
    p.set_progress_bar_config(disable=True)
    try: p.enable_attention_slicing()
    except Exception: pass
    return p


def add_lora(pipe):
    from peft import LoraConfig
    pipe.vae.requires_grad_(False); pipe.text_encoder.requires_grad_(False); pipe.unet.requires_grad_(False)
    cfg=LoraConfig(r=4,lora_alpha=4,lora_dropout=0.0,bias="none",target_modules=TARGETS)
    pipe.unet.add_adapter(cfg)
    return [p for p in pipe.unet.parameters() if p.requires_grad]


def load_lora_state(pipe,path):
    if not path.exists(): return False
    d=torch.load(path,map_location="cpu")
    pipe.unet.load_state_dict(d["state_dict"],strict=False)
    return True


def save_lora_state(pipe,path,val_loss,meta=None):
    st={k:v.detach().cpu() for k,v in pipe.unet.state_dict().items() if "lora_" in k}
    torch.save({"config":{"r":4,"alpha":4,"targets":TARGETS},"state_dict":st,"real_validation_loss":float(val_loss),"meta":meta or {}},path)
    return float(sum(v.float().norm().item() for v in st.values()))


def encode_cases(pipe,paths,seed_base):
    from diffusers import DDPMScheduler
    from torchvision.transforms.functional import to_tensor
    scheduler=DDPMScheduler.from_config(pipe.scheduler.config); cases=[]
    for i,p in enumerate(paths):
        im=prep_image(p,128,False); pix=to_tensor(im).unsqueeze(0)*2-1
        with torch.no_grad():
            lat=pipe.vae.encode(pix).latent_dist.mean*pipe.vae.config.scaling_factor
            tok=pipe.tokenizer(PROMPT,padding="max_length",max_length=pipe.tokenizer.model_max_length,truncation=True,return_tensors="pt")
            hid=pipe.text_encoder(tok.input_ids)[0]
        gen=torch.Generator(device="cpu").manual_seed(seed_base+i); noise=torch.randn(lat.shape,generator=gen,dtype=lat.dtype)
        t=torch.tensor([180+170*i],dtype=torch.long); noisy=scheduler.add_noise(lat,noise,t)
        target=noise if scheduler.config.prediction_type=="epsilon" else scheduler.get_velocity(lat,noise,t)
        cases.append((noisy,t,hid,target))
    return scheduler,cases


def eval_cases(pipe,cases):
    pipe.unet.eval(); vals=[]
    with torch.no_grad():
        for noisy,t,hid,target in cases:
            pred=pipe.unet(noisy,t,encoder_hidden_states=hid).sample; vals.append(float(F.mse_loss(pred.float(),target.float())))
    return float(np.mean(vals)),vals


def generate(pipe,path,seed=SEED+222):
    pipe.unet.eval(); g=torch.Generator(device="cpu").manual_seed(seed); t0=time.time()
    with torch.inference_mode(): im=pipe(PROMPT,num_inference_steps=10,guidance_scale=6.5,height=256,width=256,generator=g).images[0]
    im.save(path); return time.time()-t0


def train_candidate(model_id,train_paths,val_paths,out,steps):
    from diffusers import DDPMScheduler
    from torchvision.transforms.functional import to_tensor
    pipe=make_pipe(model_id); params=add_lora(pipe); resumed=load_lora_state(pipe,out/'sd_unet_lora.pt')
    if not resumed: raise RuntimeError('incumbent SD LoRA missing; refusing non-continuation training'); resumed=load_lora_state(pipe,out/'sd_unet_lora.pt')
    if not resumed: raise RuntimeError('incumbent SD LoRA missing; refusing non-continuation training'); resumed=load_lora_state(pipe,out/'sd_unet_lora.pt')
    if not resumed: raise RuntimeError('incumbent SD LoRA missing; refusing non-continuation training'); resumed=load_lora_state(pipe,out/'sd_unet_lora.pt')
    if not resumed: raise RuntimeError('incumbent SD LoRA missing; refusing non-continuation training'); resumed=load_lora_state(pipe,out/'sd_unet_lora.pt')
    if not resumed: raise RuntimeError('incumbent SD LoRA missing; refusing non-continuation training'); resumed=load_lora_state(pipe,out/'sd_unet_lora.pt')
    if not resumed: raise RuntimeError('incumbent SD LoRA missing; refusing non-continuation training'); resumed=load_lora_state(pipe,out/'sd_unet_lora.pt')
    if not resumed: raise RuntimeError('incumbent SD LoRA missing; refusing non-continuation training'); resumed=load_lora_state(pipe,out/'sd_unet_lora.pt')
    if not resumed: raise RuntimeError('incumbent SD LoRA missing; refusing non-continuation training'); resumed=load_lora_state(pipe,out/'sd_unet_lora.pt')
    if not resumed: raise RuntimeError('incumbent SD LoRA missing; refusing non-continuation training'); resumed=load_lora_state(pipe,out/'sd_unet_lora.pt')
    if not resumed: raise RuntimeError('incumbent SD LoRA missing; refusing non-continuation training'); resumed=load_lora_state(pipe,out/'sd_unet_lora.pt')
    if not resumed: raise RuntimeError('incumbent SD LoRA missing; refusing non-continuation training'); resumed=load_lora_state(pipe,out/'sd_unet_lora.pt')
    if not resumed: raise RuntimeError('incumbent SD LoRA missing; refusing non-continuation training'); resumed=load_lora_state(pipe,out/'sd_unet_lora.pt')
    if not resumed: raise RuntimeError('incumbent SD LoRA missing; refusing non-continuation training'); resumed=load_lora_state(pipe,out/'sd_unet_lora.pt')
    if not resumed: raise RuntimeError('incumbent SD LoRA missing; refusing non-continuation training'); resumed=load_lora_state(pipe,out/'sd_unet_lora.pt')
    if not resumed: raise RuntimeError('incumbent SD LoRA missing; refusing non-continuation training')
    ntrain=sum(p.numel() for p in params); ntotal=sum(p.numel() for p in pipe.unet.parameters()); scheduler=DDPMScheduler.from_config(pipe.scheduler.config)
    _,val_cases=encode_cases(pipe,val_paths,SEED+5000); base_val,base_each=eval_cases(pipe,val_cases); generate(pipe,out/"real_base.png")
    opt=torch.optim.AdamW(params,lr=6e-5,weight_decay=1e-4); losses=[]
    for step in range(steps):
        p=train_paths[step%len(train_paths)]; im=prep_image(p,128,True,SEED+step); pix=to_tensor(im).unsqueeze(0)*2-1
        with torch.no_grad():
            lat=pipe.vae.encode(pix).latent_dist.sample()*pipe.vae.config.scaling_factor
            tok=pipe.tokenizer(PROMPT,padding="max_length",max_length=pipe.tokenizer.model_max_length,truncation=True,return_tensors="pt"); hid=pipe.text_encoder(tok.input_ids)[0]
        g=torch.Generator(device="cpu").manual_seed(SEED+7000+step); noise=torch.randn(lat.shape,generator=g,dtype=lat.dtype)
        t=torch.tensor([int(80+(step*137)%850)],dtype=torch.long); noisy=scheduler.add_noise(lat,noise,t)
        target=noise if scheduler.config.prediction_type=="epsilon" else scheduler.get_velocity(lat,noise,t)
        pipe.unet.train(); pred=pipe.unet(noisy,t,encoder_hidden_states=hid).sample
        loss=F.mse_loss(pred.float(),target.float()); opt.zero_grad(); loss.backward(); torch.nn.utils.clip_grad_norm_(params,1.0); opt.step(); losses.append(float(loss.detach()))
    cand_val,cand_each=eval_cases(pipe,val_cases); cand_path=out/"sd_real_candidate.pt"; norm=save_lora_state(pipe,cand_path,cand_val,{"source":"real Drosophila images"}); infer=generate(pipe,out/"real_candidate.png")
    del pipe; gc.collect()
    return {"trainable_parameters":ntrain,"total_unet_parameters":ntotal,"steps":steps,"base_real_validation_loss":base_val,"candidate_real_validation_loss":cand_val,"candidate_improvement_vs_base":(base_val-cand_val)/max(base_val,1e-12),"base_each":base_each,"candidate_each":cand_each,"train_loss_first":losses[0],"train_loss_last":losses[-1],"lora_weight_norm_sum":norm,"candidate_path":str(cand_path),"inference_seconds":infer}


def eval_incumbent(model_id,incumbent,val_paths,out):
    pipe=make_pipe(model_id); add_lora(pipe); loaded=load_lora_state(pipe,incumbent)
    _,cases=encode_cases(pipe,val_paths,SEED+5000); val,each=eval_cases(pipe,cases); infer=generate(pipe,out/"real_incumbent.png")
    del pipe; gc.collect(); return {"loaded":loaded,"real_validation_loss":val,"each":each,"inference_seconds":infer}


def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--images",type=Path,required=True); ap.add_argument("--out",type=Path,default=Path("lora_results")); ap.add_argument("--steps",type=int,default=72)
    a=ap.parse_args(); a.out.mkdir(parents=True,exist_ok=True); t0=time.time(); imgs=sorted([p for p in a.images.iterdir() if p.suffix.lower() in {".jpg",".jpeg",".png"}])
    if len(imgs)<6: raise RuntimeError(f"need >=6 real fly images, got {len(imgs)}")
    train_paths=imgs[:4]; val_paths=imgs[4:6]; model_id=os.getenv("FLY_SD_TRAIN","segmind/tiny-sd"); incumbent_path=a.out/"sd_unet_lora.pt"
    incumbent=eval_incumbent(model_id,incumbent_path,val_paths,a.out); candidate=train_candidate(model_id,train_paths,val_paths,a.out,a.steps)
    inc=float(incumbent["real_validation_loss"]); cand=float(candidate["candidate_real_validation_loss"]); selected="candidate" if cand < inc else "incumbent"
    if selected=="candidate": shutil.copy2(a.out/"sd_real_candidate.pt",incumbent_path)
    result={"seed":SEED,"model":model_id,"selection_metric":"held-out real Drosophila fixed denoising loss (lower is better)","license_note":"Training images: Obbard Lab Drosophilidae photos, CC BY-NC 4.0 for academic/non-commercial use; attribution retained in REAL_IMAGE_SOURCES.txt.","train_images":[p.name for p in train_paths],"validation_images":[p.name for p in val_paths],"incumbent":incumbent,"candidate":candidate,"selected":selected,"selected_loss":min(inc,cand),"relative_gain_over_incumbent":max(0.0,(inc-cand)/max(inc,1e-12)),"total_seconds":time.time()-t0}
    (a.out/"real_sd_evolution.json").write_text(json.dumps(result,indent=2),encoding="utf-8"); print(json.dumps(result,indent=2))

if __name__=="__main__": main()

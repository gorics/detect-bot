#!/usr/bin/env python3
"""Real-data visual feedback between FlyBrain readout and Stable Diffusion LoRA.

Actual image pixels -> retinotopic features -> 63-group connectome dynamics ->
neural cross-attention conditioning inside SD UNet -> predicted pixels ->
connectome feedback. This is a model, NOT reconstructed fly perception.
"""
import argparse
import hashlib
import json
import time
from pathlib import Path

import numpy as np
from PIL import Image

from flybrain_neural_speech import connectome_matrix, champion

VISUAL_GROUPS=(0,1,2,3,4,5)
PROMPT="scientific macro photograph of Drosophila melanogaster with transparent wings and red compound eyes"
SEED=20261009


def preprocess(path,size=128):
    image=Image.open(path).convert("RGB")
    return image.resize((size,size),Image.Resampling.LANCZOS)


def retina(image,previous=None):
    """Image-derived features. This is a computational approximation, not compound-eye physiology."""
    rgb=np.asarray(image.resize((64,64)),dtype=np.float32)/255.
    gray=rgb@np.array([0.299,0.587,0.114],dtype=np.float32)
    dx=np.abs(gray[:,1:]-gray[:,:-1]).mean()
    dy=np.abs(gray[1:,:]-gray[:-1,:]).mean()
    diff=0.0
    if previous is not None:
        earlier=np.asarray(previous.resize((64,64)).convert("RGB"),dtype=np.float32)/255.
        diff=float(np.abs(gray-(earlier@np.array([0.299,0.587,0.114],dtype=np.float32))).mean())
    # all features grounded in pixels, mapped only to anatomically visual group indices
    return np.array([gray.mean(),float(gray.std()),dx,dy,abs(dx-dy),diff],dtype=np.float32)


def neural_step(Wn,state,image,previous=None):
    signal=np.zeros(63,np.float32)
    feats=retina(image,previous)
    signal[list(VISUAL_GROUPS)]=feats
    x=state.copy()
    for i in range(14):
        x=np.tanh(1.70*(Wn.T@x)+(.7 if i<4 else .2)*signal)
    return x.astype(np.float32),feats


def sd_model(checkpoint,model_id):
    import torch
    from diffusers import StableDiffusionPipeline
    from peft import LoraConfig
    if not checkpoint.is_file():
        raise FileNotFoundError("Real-photo SD LoRA incumbent checkpoint required: "+str(checkpoint))
    p=StableDiffusionPipeline.from_pretrained(model_id,torch_dtype=torch.float32,safety_checker=None,
                                              requires_safety_checker=False).to("cpu")
    p.set_progress_bar_config(disable=True)
    p.enable_attention_slicing()
    p.unet.requires_grad_(False)
    p.vae.requires_grad_(False)
    p.text_encoder.requires_grad_(False)
    p.unet.add_adapter(LoraConfig(r=4,lora_alpha=4,lora_dropout=0.0,bias="none",
                                  target_modules=["to_q","to_k","to_v","to_out.0"]))
    obj=torch.load(checkpoint,map_location="cpu",weights_only=True)
    state=obj["state_dict"]
    adapter_keys={k for k in p.unet.state_dict() if "lora_" in k}
    if not adapter_keys or set(state)!=adapter_keys:
        raise RuntimeError("SD LoRA checkpoint adapter keys mismatch; no random fallback: "+
                           str((len(state),len(adapter_keys))))
    incompatible=p.unet.load_state_dict(state,strict=False)
    if incompatible.unexpected_keys or any("lora_" in k for k in incompatible.missing_keys):
        raise RuntimeError("Existing SD LoRA was not fully restored")
    for par in p.unet.parameters(): par.requires_grad_(False)
    return p


def cases(pipe,photos,Wn,seed_base):
    import torch
    from diffusers import DDPMScheduler
    from torchvision.transforms.functional import to_tensor
    scheduler=DDPMScheduler.from_config(pipe.scheduler.config)
    tok=pipe.tokenizer(PROMPT,padding="max_length",max_length=pipe.tokenizer.model_max_length,
                       truncation=True,return_tensors="pt")
    with torch.no_grad():
        base_hidden=pipe.text_encoder(tok.input_ids)[0].detach()
    output=[]
    for i,path in enumerate(photos):
        picture=preprocess(path)
        visual_state,features=neural_step(Wn,np.zeros(63,np.float32),picture)
        pix=to_tensor(picture).unsqueeze(0)*2-1
        with torch.no_grad():
            latent=pipe.vae.encode(pix).latent_dist.mean*pipe.vae.config.scaling_factor
        generator=torch.Generator(device="cpu").manual_seed(seed_base+i)
        noise=torch.randn(latent.shape,generator=generator,dtype=latent.dtype)
        t=torch.tensor([180+170*i],dtype=torch.long)
        noisy=scheduler.add_noise(latent,noise,t)
        target=noise if scheduler.config.prediction_type=="epsilon" else scheduler.get_velocity(latent,noise,t)
        output.append(dict(path=path,image=picture,state=torch.from_numpy(visual_state).unsqueeze(0),
                           features=features,noisy=noisy,t=t,target=target,hidden=base_hidden,
                           latent=latent))
    return output,scheduler


def predict_noise(pipe,bridge,case):
    hidden=case["hidden"]+bridge(case["state"]).unsqueeze(1)
    return pipe.unet(case["noisy"],case["t"],encoder_hidden_states=hidden).sample


def score(pipe,bridge,dataset):
    import torch
    import torch.nn.functional as F
    bridge.eval()
    scores=[]
    with torch.inference_mode():
        for x in dataset:
            pred=predict_noise(pipe,bridge,x)
            scores.append(float(F.mse_loss(pred.float(),x["target"].float())))
    return scores


def render_feedback(pipe,bridge,case,scheduler,Wn,out,steps=3):
    import torch
    from torchvision.transforms.functional import to_pil_image
    bridge.eval()
    prev=None
    state=case["state"][0].numpy().copy()
    original=case["image"]
    original.save(out/"observed_real_photo.png")
    history=[]
    # The same actual photo supplies the initial latent; thereafter predicted visual feedback
    # changes the connectome state, which changes SD conditioning for the next prediction.
    noisy=case["noisy"]
    for i in range(steps):
        with torch.inference_mode():
            cond=case["hidden"]+bridge(torch.from_numpy(state).unsqueeze(0)).unsqueeze(1)
            prediction=pipe.unet(noisy,case["t"],encoder_hidden_states=cond).sample
            alpha=scheduler.alphas_cumprod[case["t"][0]]
            if scheduler.config.prediction_type=="epsilon":
                latent=(noisy-(1-alpha).sqrt()*prediction)/alpha.sqrt()
            else:
                latent=alpha.sqrt()*noisy-(1-alpha).sqrt()*prediction
            decoded=pipe.vae.decode(latent/pipe.vae.config.scaling_factor).sample
            visual=to_pil_image(((decoded[0].clamp(-1,1)+1)/2).clamp(0,1))
        visual.save(out/("sd_feedback_%02d.png"%i))
        state,features=neural_step(Wn,state,visual,prev if prev is not None else original)
        prev=visual
        history.append(dict(tick=i+1,neural_state_norm=float(np.linalg.norm(state)),
                            visual_features=[float(v) for v in features],
                            photo_source=str(case["path"].name),
                            feedback_image="sd_feedback_%02d.png"%i))
    return history


def main():
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix",type=Path,help="Preaggregated 63x63 connectome")
    parser.add_argument("--flybrain",type=Path,help="FlyBrain checkout (data/connectome.bin.gz)")
    parser.add_argument("--readout",type=Path,default=Path("results/state/best_genome.npz"))
    parser.add_argument("--sd-lora",type=Path,default=Path("lora_results/sd_unet_lora.pt"))
    parser.add_argument("--photos",type=Path,required=True)
    parser.add_argument("--out",type=Path,default=Path("visual_closed_loop_results"))
    parser.add_argument("--model",default="segmind/tiny-sd")
    parser.add_argument("--steps",type=int,default=12)
    parser.add_argument("--seed",type=int,default=SEED)
    a=parser.parse_args()
    if (a.matrix is None)==(a.flybrain is None):
        parser.error("Specify one of --matrix or --flybrain")
    if a.steps<1: parser.error("--steps must be positive")
    a.out.mkdir(parents=True,exist_ok=True)
    images=sorted(p for p in a.photos.iterdir() if p.suffix.lower() in (".jpg",".jpeg",".png"))
    if len(images)<6: raise RuntimeError("At least six real Drosophila images required")
    train,val=images[:4],images[4:6]
    hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in train+val}
    if len(set(hashes.values()))!=6: raise RuntimeError("Duplicate actual image content across splits")
    W= np.load(a.matrix,allow_pickle=False) if a.matrix else connectome_matrix(a.flybrain/"data/connectome.bin.gz")
    if W.shape!=(63,63): raise ValueError("Invalid connectome matrix")
    Wn=W/np.maximum(np.sum(np.abs(W),axis=1,keepdims=True),1e-6)
    readout_W,readout_B=champion(a.readout)
    readout_hash=hashlib.sha256(a.readout.read_bytes()).hexdigest()
    sd_hash=hashlib.sha256(a.sd_lora.read_bytes()).hexdigest()
    # Fixed evaluation random seeds; generation-specific training seeds.
    existing=a.out/"bridge_champion.pt"
    previous=a.out/"results.json"
    generation=(int(json.loads(previous.read_text()).get("generation",0)) if previous.exists() else 0)+1
    torch.manual_seed(a.seed+generation*101)
    pipe=sd_model(a.sd_lora,a.model)
    tr,_=cases(pipe,train,Wn,a.seed+7500+generation*100)
    va,scheduler=cases(pipe,val,Wn,SEED+5000)
    dim=va[0]["hidden"].shape[-1]
    bridge=nn.Linear(63,dim,bias=False)
    torch.nn.init.zeros_(bridge.weight)
    resumed=existing.exists()
    if resumed:
        old=torch.load(existing,map_location="cpu",weights_only=True)
        bridge.load_state_dict(old["bridge_state"],strict=True)
    incumbent_scores=score(pipe,bridge,va)
    candidate=nn.Linear(63,dim,bias=False)
    candidate.load_state_dict(bridge.state_dict(),strict=True)
    opt=torch.optim.AdamW(candidate.parameters(),lr=0.003,weight_decay=0.01)
    training_losses=[]
    for step in range(a.steps):
        obj=tr[step%len(tr)]
        candidate.train()
        pred=predict_noise(pipe,candidate,obj)
        loss=F.mse_loss(pred.float(),obj["target"].float())
        opt.zero_grad()
        loss.backward()
        torch.nn.utils.clip_grad_norm_(candidate.parameters(),1.0)
        opt.step()
        training_losses.append(float(loss.detach()))
    candidate_scores=score(pipe,candidate,va)
    incumbent=float(np.mean(incumbent_scores))
    challenger=float(np.mean(candidate_scores))
    # Never promote based on training or self-distillation.
    accepted=bool(challenger<incumbent and all(c<i for c,i in zip(candidate_scores,incumbent_scores)))
    torch.save({"bridge_state":candidate.state_dict(),"validation_real_photo_mse":challenger,
                "generation":generation},a.out/"bridge_candidate.pt")
    if accepted:
        torch.save({"bridge_state":candidate.state_dict(),"validation_real_photo_mse":challenger,
                    "generation":generation},existing)
    active=candidate if accepted else bridge
    # Actual Stable-Diffusion VAE/UNet -> image -> anatomical connectome -> SD conditioning loop
    feedback=render_feedback(pipe,active,va[0],scheduler,Wn,a.out)
    # Determine whether changing visual input actually changes neural state
    states=[neural_step(Wn,np.zeros(63,np.float32),c["image"])[0] for c in va]
    state_separation=float(np.linalg.norm(states[0]-states[1]))
    # Readout is used on visual states, without asserting semantic generalization
    behavior=[]
    for s in states:
        logits=readout_W@s+readout_B
        behavior.append(["food","touch","air","light","warm","cool"][int(logits.argmax())])
    report=dict(generation=generation,model=a.model,source="real Drosophila photographs",
        train_files=[p.name for p in train],held_out_files=[p.name for p in val],
        image_sha256=hashes,connectome_group_count=63,readout_sha256=readout_hash,
        sd_lora_sha256=sd_hash,sd_lora_restored=True,readout_restored=True,
        bridge_resumed=resumed,bridge_train_steps=a.steps,
        baseline_heldout_real_photo_mse=incumbent,candidate_heldout_real_photo_mse=challenger,
        baseline_per_photo=incumbent_scores,candidate_per_photo=candidate_scores,
        champion_promoted=accepted,strict_gate="mean lower AND both held-out photos individually improve",
        training_loss_first=training_losses[0],training_loss_last=training_losses[-1],
        feedback_trace=feedback,heldout_input_brain_state_l2=state_separation,
        heldout_readout_labels=behavior,
        caveat="Neural states are connectome simulations and visual features engineered from photos, NOT measured subjective thoughts or true fly retinal reconstruction.")
    (a.out/"results.json").write_text(json.dumps(report,ensure_ascii=False,indent=2))
    print(json.dumps(report,ensure_ascii=False,indent=2))
    assert hashlib.sha256(a.readout.read_bytes()).hexdigest()==readout_hash
    assert hashlib.sha256(a.sd_lora.read_bytes()).hexdigest()==sd_hash

if __name__=="__main__": main()

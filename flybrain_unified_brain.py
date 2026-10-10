#!/usr/bin/env python3
"""One recurrent FlyBrain workspace jointly trained through real LM and SD LoRA.
Not a whole-neuron biological replica or a decoder of subjective experience.
"""
import argparse, hashlib, json, os, random, time
from pathlib import Path
import numpy as np
import torch
from torch import nn
import torch.nn.functional as F
from PIL import Image
from flybrain_neural_speech import connectome_matrix

KINDS=("food","touch","air","light","warm","cool")
STIMULI=((6,32,37),(10,35),(11,5,35),(0,2,25),(14,35),(15,35))
KOREAN=(
    "먹이에 접근하여 먹을 가능성이 있습니다.",
    "접촉에 반응하여 몸단장할 가능성이 있습니다.",
    "기류를 감지하여 회피할 가능성이 있습니다.",
    "밝은 방향으로 탐색할 가능성이 있습니다.",
    "더운 곳을 벗어날 가능성이 있습니다.",
    "차가운 자극에 이동을 줄일 가능성이 있습니다.",
)
PROMPT="scientific macro photograph of a real Drosophila melanogaster with transparent wings and red eyes"
SEED=20261010

def image_features(image, previous=None):
    a=np.asarray(image.resize((64,64)).convert("RGB"),dtype=np.float32)/255.
    gray=a@np.array([.299,.587,.114],np.float32)
    dx=float(np.abs(gray[:,1:]-gray[:,:-1]).mean())
    dy=float(np.abs(gray[1:,:]-gray[:-1,:]).mean())
    motion=0.0
    if previous is not None:
        b=np.asarray(previous.resize((64,64)).convert("RGB"),dtype=np.float32)/255.
        motion=float(np.abs(gray-b@np.array([.299,.587,.114],np.float32)).mean())
    return torch.tensor([[float(gray.mean()),float(gray.std()),dx,dy,abs(dx-dy),motion]],dtype=torch.float32)

class Workspace(nn.Module):
    def __init__(self, matrix, readout_W, readout_B):
        super().__init__()
        w=torch.tensor(matrix,dtype=torch.float32)
        w=w/w.abs().sum(1,keepdim=True).clamp_min(1e-6)
        self.register_buffer("anatomy",w)
        self.plasticity=nn.Parameter(torch.zeros(63,63))
        self.readout=nn.Linear(63,6)
        with torch.no_grad():
            self.readout.weight.copy_(torch.tensor(readout_W))
            self.readout.bias.copy_(torch.tensor(readout_B))
        self.readout.requires_grad_(False)
    def forward(self,visual,kind_index,old_state=None):
        stim=torch.zeros((visual.shape[0],63),dtype=visual.dtype,device=visual.device)
        stim[:,0:6]=visual
        for idx in STIMULI[kind_index]: stim[:,idx]+=0.9
        w=self.anatomy + 0.05*torch.tanh(self.plasticity)
        x=torch.zeros_like(stim) if old_state is None else old_state
        for k in range(12):
            x=torch.tanh(1.70*(x@w)+ (1.0 if k<4 else 0.3)*stim)
        return x,self.readout(x)

class OneBrain(nn.Module):
    def __init__(self,workspace,lm,unet,lm_dim,sd_dim):
        super().__init__()
        self.core=workspace
        self.lm=lm
        self.unet=unet
        self.lm_bridge=nn.Linear(63,lm_dim,bias=False)
        self.sd_bridge=nn.Linear(63,sd_dim,bias=False)
        nn.init.zeros_(self.lm_bridge.weight)
        nn.init.zeros_(self.sd_bridge.weight)
    def language_loss(self,state,tok,kind):
        p=tok.encode("Simulated fly neural signal. Describe the likely behavior in Korean: ",
                     add_special_tokens=False)
        t=tok.encode(KOREAN[kind]+tok.eos_token,add_special_tokens=False)
        ids=torch.tensor([p+t],dtype=torch.long)
        labels=ids.clone()
        labels[:,:len(p)]=-100
        emb=self.lm.get_input_embeddings()(ids)
        cond=emb+0.15*self.lm_bridge(state).unsqueeze(1)
        output=self.lm(inputs_embeds=cond,attention_mask=torch.ones_like(ids),labels=labels)
        return output.loss,output.logits
    def diffusion_loss(self,state,case):
        cond=case["hidden"]+self.sd_bridge(state).unsqueeze(1)
        output=self.unet(case["noisy"],case["t"],encoder_hidden_states=cond).sample
        return F.mse_loss(output.float(),case["target"].float()),output

def load_models(lm_adapter,sd_adapter,model_id,pipe_id):
    from transformers import AutoModelForCausalLM,AutoTokenizer
    from peft import PeftModel,LoraConfig
    from diffusers import StableDiffusionPipeline
    if not (lm_adapter/"adapter_model.safetensors").is_file():
        raise FileNotFoundError("Prior SmolLM2 LoRA adapter missing")
    if not sd_adapter.is_file(): raise FileNotFoundError("Prior SD LoRA missing")
    tok=AutoTokenizer.from_pretrained(model_id)
    base=AutoModelForCausalLM.from_pretrained(model_id,torch_dtype=torch.float32)
    lm=PeftModel.from_pretrained(base,lm_adapter,is_trainable=True)
    pipe=StableDiffusionPipeline.from_pretrained(pipe_id,torch_dtype=torch.float32,
        safety_checker=None,requires_safety_checker=False).to("cpu")
    pipe.set_progress_bar_config(disable=True)
    pipe.enable_attention_slicing()
    pipe.vae.requires_grad_(False);pipe.text_encoder.requires_grad_(False);pipe.unet.requires_grad_(False)
    pipe.unet.add_adapter(LoraConfig(r=4,lora_alpha=4,lora_dropout=0.0,bias="none",
        target_modules=["to_q","to_k","to_v","to_out.0"]))
    d=torch.load(sd_adapter,map_location="cpu",weights_only=True)
    keys={k for k in pipe.unet.state_dict() if "lora_" in k}
    if not keys or set(d["state_dict"])!=keys:
        raise RuntimeError("SD LoRA checkpoint not compatible with this UNet")
    info=pipe.unet.load_state_dict(d["state_dict"],strict=False)
    if info.unexpected_keys or any("lora_" in k for k in info.missing_keys):
        raise RuntimeError("SD LoRA restore incomplete")
    lm_dim=lm.get_input_embeddings().weight.shape[1]
    tok_ids=pipe.tokenizer(PROMPT,padding="max_length",
              max_length=pipe.tokenizer.model_max_length,truncation=True,return_tensors="pt")
    with torch.no_grad():
        hidden=pipe.text_encoder(tok_ids.input_ids)[0].detach()
    return lm,tok,pipe,lm_dim,hidden

def make_case(pipe,photo,hidden,noise_seed,tick):
    from diffusers import DDPMScheduler
    image=Image.open(photo).convert("RGB").resize((128,128),Image.Resampling.LANCZOS)
    a=np.array(image,dtype=np.float32)/127.5-1.
    pixels=torch.from_numpy(a).permute(2,0,1).unsqueeze(0)
    with torch.no_grad():
        latent=pipe.vae.encode(pixels).latent_dist.mean*pipe.vae.config.scaling_factor
    scheduler=DDPMScheduler.from_config(pipe.scheduler.config)
    g=torch.Generator(device="cpu").manual_seed(noise_seed)
    noise=torch.randn(latent.shape,generator=g,dtype=latent.dtype)
    t=torch.tensor([tick],dtype=torch.long)
    noisy=scheduler.add_noise(latent,noise,t)
    target=noise if scheduler.config.prediction_type=="epsilon" else scheduler.get_velocity(latent,noise,t)
    return dict(photo=photo,image=image,visual=image_features(image),noisy=noisy,t=t,
                hidden=hidden,target=target,scheduler=scheduler)

def lora_state(module):
    return {k:v.detach().cpu().clone() for k,v in module.state_dict().items()
            if "lora_" in k}

def apply_lora(module,state):
    keys={k for k in module.state_dict() if "lora_" in k}
    if not keys or keys!=set(state): raise ValueError("Unified LoRA key mismatch")
    d=module.load_state_dict(state,strict=False)
    if d.unexpected_keys or any("lora_" in k for k in d.missing_keys):
        raise ValueError("Unified LoRA was incompletely resumed")

def extract(m):
    return dict(core={k:v.detach().cpu().clone() for k,v in m.core.state_dict().items()},
        lm_bridge=m.lm_bridge.state_dict(),sd_bridge=m.sd_bridge.state_dict(),
        lm_lora=lora_state(m.lm),sd_lora=lora_state(m.unet))

def restore(m,state):
    m.core.load_state_dict(state["core"])
    m.lm_bridge.load_state_dict(state["lm_bridge"])
    m.sd_bridge.load_state_dict(state["sd_bridge"])
    apply_lora(m.lm,state["lm_lora"])
    apply_lora(m.unet,state["sd_lora"])

def evaluate(m,tok,cases):
    old=m.training
    m.eval()
    records=[]
    with torch.no_grad():
        for item,kind in cases:
            x,logits=m.core(item["visual"],kind)
            sd,_=m.diffusion_loss(x,item)
            ll,_=m.language_loss(x,tok,kind)
            records.append(dict(photo=item["photo"].name,stimulus=KINDS[kind],
                                image_mse=float(sd),language_nll=float(ll),
                                action_correct=int(logits.argmax(1).item()==kind)))
    m.train(old)
    return records

def summary(rows):
    return dict(image_mse=float(np.mean([x["image_mse"] for x in rows])),
                language_nll=float(np.mean([x["language_nll"] for x in rows])),
                action_accuracy=float(np.mean([x["action_correct"] for x in rows])))

def visualize_feedback(m,pipe,item,out):
    from torchvision.transforms.functional import to_pil_image
    m.eval()
    visual=item["visual"];previous=item["image"]
    old=None
    history=[]
    with torch.no_grad():
        for n in range(3):
            x,_=m.core(visual,3,old_state=old)
            sd_loss,pred=m.diffusion_loss(x,item)
            alpha=item["scheduler"].alphas_cumprod[item["t"][0]]
            if item["scheduler"].config.prediction_type=="epsilon":
                latent=(item["noisy"]-(1-alpha).sqrt()*pred)/alpha.sqrt()
            else: latent=alpha.sqrt()*item["noisy"]-(1-alpha).sqrt()*pred
            decoded=pipe.vae.decode(latent/pipe.vae.config.scaling_factor).sample
            img=to_pil_image(((decoded[0].clamp(-1,1)+1)/2).clamp(0,1))
            name="feedback_%02d.png"%n;img.save(out/name)
            next_visual=image_features(img,previous)
            change=float(torch.linalg.vector_norm(next_visual-visual))
            history.append(dict(frame=n,image=name,image_change_l2=change,sd_loss=float(sd_loss)))
            old=x
            visual=next_visual
            previous=img
    return history

def main():
    from peft import PeftModel
    p=argparse.ArgumentParser()
    p.add_argument("--flybrain",type=Path,required=True)
    p.add_argument("--photos",type=Path,required=True)
    p.add_argument("--readout",type=Path,default=Path("results/state/best_genome.npz"))
    p.add_argument("--lm-adapter",type=Path,default=Path("lora_results/llm_lora"))
    p.add_argument("--sd-adapter",type=Path,default=Path("lora_results/sd_unet_lora.pt"))
    p.add_argument("--out",type=Path,default=Path("unified_brain_results"))
    p.add_argument("--steps",type=int,default=6)
    p.add_argument("--lm-model",default="HuggingFaceTB/SmolLM2-135M-Instruct")
    p.add_argument("--sd-model",default="segmind/tiny-sd")
    a=p.parse_args()
    if a.steps<2: p.error("at least two unified gradient updates required")
    a.out.mkdir(parents=True,exist_ok=True)
    photos=sorted(p for p in a.photos.iterdir() if p.suffix.lower() in (".jpg",".png",".jpeg"))
    if len(photos)<6: raise RuntimeError("Six real fly photographs required")
    train_photos,val_photos=photos[:4],photos[4:6]
    image_hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in photos[:6]}
    if len(set(image_hashes.values()))!=6: raise RuntimeError("duplicate photos detected")
    if not a.readout.is_file():raise FileNotFoundError("Original evolved readout champion missing")
    hashes=dict(readout=hashlib.sha256(a.readout.read_bytes()).hexdigest(),
                sd_lora=hashlib.sha256(a.sd_adapter.read_bytes()).hexdigest(),
                llm_lora=hashlib.sha256((a.lm_adapter/"adapter_model.safetensors").read_bytes()).hexdigest())
    prior=a.out/"results.json"
    generation=(int(json.loads(prior.read_text()).get("generation",0)) if prior.exists() else 0)+1
    seed=SEED+generation*701
    random.seed(seed);np.random.seed(seed);torch.manual_seed(seed)
    conn=connectome_matrix(a.flybrain/"data/connectome.bin.gz")
    with np.load(a.readout,allow_pickle=False) as z:
        W,B=z["W"].astype(np.float32),z["B"].astype(np.float32)
    if W.shape!=(6,63) or B.shape!=(6,): raise ValueError("readout dimensions")
    lm,tok,pipe,lm_dim,hidden=load_models(a.lm_adapter,a.sd_adapter,a.lm_model,a.sd_model)
    brain=OneBrain(Workspace(conn,W,B),lm,pipe.unet,lm_dim,hidden.shape[-1])
    checkpoint=a.out/"unified_champion.pt"
    resumed=checkpoint.exists()
    if resumed:
        saved=torch.load(checkpoint,map_location="cpu",weights_only=True)
        restore(brain,saved["model"])
    base_cases=[(make_case(pipe,p,hidden,SEED+2000+i,180+170*i),i)
                for i,p in enumerate(val_photos)]
    baseline_rows=evaluate(brain,tok,base_cases)
    baseline=summary(baseline_rows)
    t0=time.time()
    train_cases=[make_case(pipe,p,hidden,seed+3000+i,100+(137*i)%790)
                 for i,p in enumerate(train_photos)]
    core_params=[*brain.core.plasticity.parameters()] if hasattr(brain.core.plasticity,"parameters") else [brain.core.plasticity]
    shared=[brain.core.plasticity,*brain.lm_bridge.parameters(),*brain.sd_bridge.parameters()]
    lora_params=[p for p in brain.lm.parameters() if p.requires_grad]+[p for p in brain.unet.parameters() if p.requires_grad]
    if not lora_params: raise RuntimeError("No active LoRA parameters")
    optimizer=torch.optim.AdamW([
        {"params":shared,"lr":.002},
        {"params":lora_params,"lr":.00001}],weight_decay=1e-4)
    train_history=[]; gradients=[]
    for i in range(a.steps):
        case=train_cases[i%4]
        kind=i%6
        brain.train()
        optimizer.zero_grad()
        state,logits=brain.core(case["visual"],kind)
        # A single shared recurrent connectome receives gradients from both neural-language
        # and neural-image objectives. Backward separately to save CPU RAM; one optimizer step.
        ll,_=brain.language_loss(state,tok,kind)
        action=F.cross_entropy(logits,torch.tensor([kind]))
        (0.3*ll+0.2*action).backward()
        language_grad=float(brain.core.plasticity.grad.norm().item())
        state,_=brain.core(case["visual"],kind)
        vision,_=brain.diffusion_loss(state,case)
        vision.backward()
        total_grad=float(brain.core.plasticity.grad.norm().item())
        torch.nn.utils.clip_grad_norm_(shared+lora_params,1.0)
        optimizer.step()
        train_history.append(dict(step=i+1,sd_loss=float(vision.detach()),
                                  language_loss=float(ll.detach()),behavior_loss=float(action.detach())))
        gradients.append(dict(step=i+1,after_language=language_grad,after_both=total_grad))
    candidate_rows=evaluate(brain,tok,base_cases)
    candidate=summary(candidate_rows)
    sd_per=all(a["image_mse"]<b["image_mse"] for a,b in zip(candidate_rows,baseline_rows))
    promoted=bool(candidate["image_mse"]<baseline["image_mse"] and sd_per and
                  candidate["language_nll"]<baseline["language_nll"] and
                  candidate["action_accuracy"]>=baseline["action_accuracy"])
    trained_state=extract(brain)
    torch.save({"generation":generation,"model":trained_state,"validation":candidate},
               a.out/"unified_candidate.pt")
    if promoted:
        torch.save({"generation":generation,"model":trained_state,"validation":candidate},checkpoint)
    # Trained challenger drives the experimental loop, but cannot overwrite champion on regression.
    feedback=visualize_feedback(brain,pipe,base_cases[0][0],a.out)
    with torch.no_grad():
        brain.eval()
        v,_=brain.core(base_cases[0][0]["visual"],base_cases[0][1])
        sd_on,_=brain.diffusion_loss(v,base_cases[0][0])
        sd_pred=brain.unet(base_cases[0][0]["noisy"],base_cases[0][0]["t"],
               encoder_hidden_states=base_cases[0][0]["hidden"]+
               brain.sd_bridge(v).unsqueeze(1)).sample
        zero_pred=brain.unet(base_cases[0][0]["noisy"],base_cases[0][0]["t"],
               encoder_hidden_states=base_cases[0][0]["hidden"]+
               brain.sd_bridge(torch.zeros_like(v)).unsqueeze(1)).sample
        ablation=float(torch.abs(sd_pred-zero_pred).mean())
    result=dict(generation=generation,architecture="one recurrent connectome state, shared language+vision gradients, single optimizer, fused checkpoint",
        actual_neurons_in_connectome=139255,actual_edges_in_connectome=2698236,
        compressed_recurrent_neural_groups=63,prior_readout_restored=True,
        prior_smollm2_lora_restored=True,prior_sd_lora_restored=True,
        prior_unified_champion_resumed=resumed,train_steps=a.steps,
        image_sha256=image_hashes,baseline=baseline,candidate=candidate,
        per_case_baseline=baseline_rows,per_case_candidate=candidate_rows,
        champion_promoted=promoted,
        sd_neural_conditioning_ablation_mae=ablation,
        joint_gradient_norms=gradients,train_history=train_history,
        feedback=feedback,source_checkpoint_sha256=hashes,seconds=time.time()-t0,
        champion_gate="Both real-photo held-out SD losses improve, Korean LM held-out NLL decreases, synthetic stimulus accuracy does not decrease",
        qualification="Actual FlyBrain connectome coarse-grained to 63 groups; actual pretrained LLM and SD LoRA compute inside a single shared optimizer. This is NOT measured fly perception, consciousness or a neuron-level biological brain.")
    (a.out/"results.json").write_text(json.dumps(result,ensure_ascii=False,indent=2))
    for key,path in [("readout",a.readout),("sd_lora",a.sd_adapter),
                     ("llm_lora",a.lm_adapter/"adapter_model.safetensors")]:
        assert hashlib.sha256(path.read_bytes()).hexdigest()==hashes[key],key+" changed"
    print(json.dumps(result,ensure_ascii=False,indent=2))

if __name__=="__main__":
    main()

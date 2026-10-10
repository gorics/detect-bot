# FlyBrain one-brain joint language + vision training

## What this actually is
A real PyTorch **one-optimizer multimodal agent**, with a *single* recurrent 63-group FlyBrain-derived neural state that feeds **both** SmolLM2-135M LoRA and Tiny-SD UNet LoRA. The readout champion, SmolLM2 LoRA and real-photo SD LoRA are loaded as initialization and the original assets are never overwritten. A **joint candidate checkpoint** holds the trainable central recurrent workspace, neural-to-language and neural-to-SD projections, both LoRAs, and the readout buffer. The two pretrained base model weights remain separate read-only pretrained backbones and are required for inference; the joint checkpoint does not contain their full several-hundred-million parameters.

This is functional shared-state/gradient integration, **not** biological single-cell fusion or proof of consciousness.

## Actual computational steps
- Photograph of a fly -> six pixel features -> FlyBrain-derived 63-group recurrent state.
- An independently indicated *synthetic stimulus* affects the same 63-group state. This is a simulation task; photographs are not behavior labels and the model is not decoding a real fly's visual perspective.
- Frozen evolved readout interprets state for six synthetic stimuli.
- Shared state conditions token embeddings of SmolLM2 with *its real trained LoRA* for a Korean behavior caption.
- The **same shared state** conditions cross-attention of Tiny-SD UNet with *its real-photo SD LoRA*, using VAE-encoded real photos as denoising targets.
- Loss from **both** real pretrained models backpropagates through the same workspace (including a learned plasticity matrix). Language and diffusion backward passes are accumulated before **one** optimizer step.
- Inference takes the same neural state for language and SD and routes SD-generated pixel feedback back through visual features into the recurrent workspace over three frames.
- The champion gate is strict: held-out real-photo SD denoising loss decreases on BOTH images, Korean language NLL decreases, and synthetic action prediction does not regress.
- Images have SHA-256 hashes. Held-out images are not used for gradient updates.
- Each run saves JSON metrics, experimental inference frames, and a unified candidate checkpoint; it promotes a unified champion only when all constraints pass.

## Scientific limitations
- The connectome was **aggregated** into 63 functional groups. This is not a simulation of all 139,255 neurons with membrane dynamics.
- The source visual inputs are photos *of* Drosophila, not first-person fly-eye observations.
- There are only two held-out real photographs: results cannot demonstrate broad generalization.
- Joint training and causal model ablation show information flow and gradient sharing, **not** subjective thought-reading, general artificial intelligence or a real biological brain.
- The Korean text is a model output on simulated behavior; not a statement from a living insect.
- Repeatedly optimizing against the same two photos may overfit. Expand the independent held-out test before making improvement claims.

## Reproduce
GitHub Actions: [.github/workflows/flybrain-one-brain.yml](.github/workflows/flybrain-one-brain.yml)
Implementation: [flybrain_unified_brain.py](flybrain_unified_brain.py)

Requirements: Python 3.11; pinned ML stack in Actions; copy of https://github.com/snedea/flybrain; original readout and LoRA champion checkpoints; six distinct Drosophila photographs.

~~~bash
python flybrain_unified_brain.py \
  --flybrain external/flybrain \
  --photos real_drosophila \
  --readout results/state/best_genome.npz \
  --lm-adapter lora_results/llm_lora \
  --sd-adapter lora_results/sd_unet_lora.pt \
  --out unified_brain_results --steps 6
~~~

Artifacts: unified_brain_results/results.json, unified_candidate.pt, feedback_00.png through feedback_02.png, and unified_champion.pt only when promoted. The source checkpoint SHA-256 values in the results JSON are validated unchanged by the code.

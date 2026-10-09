# FlyBrain ↔ Stable Diffusion: real-photo closed-loop experiment

## What was actually executed

This experiment uses the existing 63-group anatomical aggregation of the real FlyBrain connectome, the previous **evolved readout champion**, and the **existing real-photo Stable Diffusion Tiny-SD UNet LoRA champion**. These previously trained checkpoints must be present and are protected from modification.

On GitHub Actions, six actual Drosophila photographs are fetched from Wikimedia Commons. Four photographs serve as training inputs; two are held out for a strict denoising-loss check. Every downloaded image is content-hashed by SHA-256; duplicate inputs are refused.

Path:
1. RGB photograph is mapped to six image-derived visual features, injected into the real FlyBrain connectome's VIS_R1R6, VIS_R7R8, VIS_ME, VIS_LO, VIS_LC and VIS_LPTC *functional-group approximation*.
2. A recurrent 63-state connectome model computes the neural activity vector.
3. A trainable 63-to-text-embedding projection feeds these values **inside the actual Stable Diffusion UNet cross-attention conditioning** (not merely into a textual prompt).
4. Stable Diffusion VAE encodes the actual image. Its existing LoRA UNet predicts a noise residual. The VAE decodes the resulting denoised latent into a new image.
5. Image features from that actual decoded image re-enter the simulated neural dynamics for the next step; changed neural states affect the next UNet output.
6. An *experimental* challenger bridge always participates in the causal loop demonstration, even if held-out evaluation rejects it. A failed candidate is **never** saved as the production visual-bridge champion.
7. Only mean loss lower than the incumbent AND both held-out images individually improved can promote the bridge. Self-distillation is ignored. The saved original evolved readout and SD LoRA are never overwritten by this workflow.

Causal ablation directly compares UNet predicted noise with normal visual neural-state conditioning and the same test image with its neural state set to zero. A nonzero UNet prediction MAE means the neural signal changes actual Stable Diffusion computation. Additionally, differences between decoded feedback images can be measured from saved PNGs.

## Important scientific boundaries

- **Actual**: Drosophila photographs, anatomical group aggregated connectivity, real PyTorch model weights, real LoRA restoration, real UNet computation, real generated frame feedback, actual held-out loss and SHA-256 hashes.
- **Modeled/engineered**: visual feature approximation, neural firing/activity dynamics, neural-to-SD bridge, hypothetical behavior readout.
- **Not obtained**: a real fly's visual point of view, neural recordings from a living specimen, actual subjective thoughts, artificial self-awareness or independent open-ended cognition.
- A photo *of* a fly is not a photo *seen by* a fly. The generated feedback images are denoised reconstructions/visual predictions, not a biological vision ground truth.
- Two held-out images are far too few for reliable generalization or claims of improved fly vision.
- Reusing these two held-out photos repeatedly for candidate decisions risks test-set leakage; robust science requires more independent samples and locked final test sets.

## Run

Workflow: [FlyBrain SD Neural Vision Closed Loop](.github/workflows/flybrain-visual-closed-loop.yml)

Source: [flybrain_visual_closed_loop.py](flybrain_visual_closed_loop.py)

Prerequisites: Python 3.11, pinned Torch/torchvision/Diffusers/Transformers/PEFT dependencies, flybrain from https://github.com/snedea/flybrain, existing results/state/best_genome.npz and lora_results/sd_unet_lora.pt, six distinct real Drosophila photographs in a local photo directory.

Command:

~~~bash
python flybrain_visual_closed_loop.py \
  --flybrain external/flybrain \
  --readout results/state/best_genome.npz \
  --sd-lora lora_results/sd_unet_lora.pt \
  --photos real_drosophila \
  --out visual_closed_loop_results \
  --steps 12
~~~

Results: JSON evaluation, per-photo SHA-256, candidate bridge, and actual SD feedback PNG frames are retained as workflow artifacts. Compare these frames for pixel changes; they are experimental model outputs, not biological recordings.

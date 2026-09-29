#!/usr/bin/env python3
# V7 continues the verified V6 evolutionary search without changing the fitness domain.
# Reuse the tested V6 implementation, but namespace all persisted V7 outputs.
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
import hybrid_v6 as v6

# Expand mutation vocabulary while preserving the exact V6 fitness function/comparability.
v6.SEED = 20261002
v6.MODS = list(dict.fromkeys(v6.MODS + ['projection neuron','olfactory glomerulus','connectome tracing','dense neurites','synaptic boutons']))

_orig_save_json = v6.core.save_json
def save_json_v7(path, obj):
    p = Path(path)
    name = p.name.replace('v6','v7')
    _orig_save_json(p.with_name(name), obj)
v6.core.save_json = save_json_v7

_orig_evolve = v6.evolve
def evolve_v7(pipe,prompt0,target,outdir,previous,generations=3,population=14):
    state = _orig_evolve(pipe,prompt0,target,outdir,previous,generations,population)
    out=Path(outdir)
    old=out/'flybrain_sd_v6_final.png'; new=out/'flybrain_sd_v7_final.png'
    if old.exists(): old.replace(new)
    state['final_image']=str(new)
    # Rewrite V7 state after final image rename.
    _orig_save_json(out/'evolution_v7_state.json',state)
    return state
v6.evolve = evolve_v7

if __name__ == '__main__':
    v6.main()
    out=None
    # v6.main writes run_report_v7 via save hook, but its final_image field is already V7 from evolve_v7.

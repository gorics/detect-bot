#!/usr/bin/env python3
# V8 continues the verified V7 evolutionary search without changing the fitness domain.
# Reuse the tested V6 core implementation while namespacing all persisted V8 outputs.
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
import hybrid_v6 as v6

# Broaden morphology/search vocabulary while preserving the exact comparable V6/V7 fitness function.
v6.SEED = 20261003
v6.MODS = list(dict.fromkeys(v6.MODS + [
    'projection neuron','olfactory glomerulus','connectome tracing','dense neurites','synaptic boutons',
    'glomerular neuropil','axon tract','dendritic arbor','synaptic microcircuit','fluorescent neural tracing'
]))

_orig_save_json = v6.core.save_json
def save_json_v8(path, obj):
    p = Path(path)
    name = p.name.replace('v6','v8')
    _orig_save_json(p.with_name(name), obj)
v6.core.save_json = save_json_v8

_orig_evolve = v6.evolve
def evolve_v8(pipe, prompt0, target, outdir, previous, generations=3, population=16):
    state = _orig_evolve(pipe, prompt0, target, outdir, previous, generations, population)
    out = Path(outdir)
    old = out/'flybrain_sd_v6_final.png'
    new = out/'flybrain_sd_v8_final.png'
    if old.exists():
        old.replace(new)
    state['final_image'] = str(new)
    _orig_save_json(out/'evolution_v8_state.json', state)
    return state
v6.evolve = evolve_v8

if __name__ == '__main__':
    v6.main()

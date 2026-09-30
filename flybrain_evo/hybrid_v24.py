#!/usr/bin/env python3
# V24 continues the accepted V23 elite under the identical V6 fitness function and strict elitism.
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
import hybrid_v6 as v6

v6.SEED = 20261024
v6.MODS = list(dict.fromkeys(v6.MODS + [
    'projection neuron','olfactory glomerulus','connectome tracing','dense neurites','synaptic boutons',
    'glomerular neuropil','axon tract','dendritic arbor','synaptic microcircuit','fluorescent neural tracing',
    'antennal lobe','projection neuron tract','glomerular map','neurite bundle','synapse-rich neuropil',
    'olfactory sensory neuron','projection neuron arbor','glomerular boundaries','synaptic terminals',
    'ORN axon terminals','PN dendritic claws','glomerular innervation','antennal lobe circuit',
    'connectomic micrograph','olfactory receptor axons','projection neuron morphology',
    'connectome reconstruction','neural arborization','antennal lobe glomeruli','synaptic neuropil map',
    'ORN-PN connectivity','olfactory glomerular atlas','synaptic microdomain','antennal lobe wiring diagram',
    'connectome-derived olfactory circuit','glomerular synapse topology','projection neuron dendritic mesh',
    'ORN terminal microcircuit','antennal lobe connectomics','synapse-resolved neuropil',
    'glomerular projection field','olfactory neuropil reconstruction','ORN terminal arbor','PN dendritic territory',
    'dark background','high contrast micrograph','sparse luminous neurites','branching axon fascicles'
]))

_orig_save_json = v6.core.save_json
def save_json_v24(path, obj):
    p = Path(path)
    _orig_save_json(p.with_name(p.name.replace('v6','v24')), obj)
v6.core.save_json = save_json_v24

_orig_evolve = v6.evolve
def evolve_v24(pipe, prompt0, target, outdir, previous, generations=3, population=48):
    state = _orig_evolve(pipe, prompt0, target, outdir, previous, generations, population)
    out = Path(outdir)
    old = out/'flybrain_sd_v6_final.png'
    new = out/'flybrain_sd_v24_final.png'
    if old.exists(): old.replace(new)
    state['final_image'] = str(new)
    _orig_save_json(out/'evolution_v24_state.json', state)
    return state
v6.evolve = evolve_v24

if __name__ == '__main__':
    v6.main()

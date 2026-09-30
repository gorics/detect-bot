#!/usr/bin/env python3
# V19 continues the accepted V18 elite under the identical V6 fitness function and strict elitism.
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
import hybrid_v6 as v6

v6.SEED = 20261019
v6.MODS = list(dict.fromkeys(v6.MODS + [
    'projection neuron','olfactory glomerulus','connectome tracing','dense neurites','synaptic boutons',
    'glomerular neuropil','axon tract','dendritic arbor','synaptic microcircuit','fluorescent neural tracing',
    'olfactory projection tract','glomerular microcircuit','sparse neural arbor','dense neuropil','synaptic puncta',
    'antennal lobe','projection neuron tract','glomerular map','neurite bundle','synapse-rich neuropil',
    'olfactory sensory neuron','antennal lobe neuropil','projection neuron arbor','glomerular boundaries',
    'synaptic terminals','neuronal morphology','ORN axon terminals','PN dendritic claws',
    'glomerular innervation','antennal lobe circuit','neuropil compartment','synaptic connectivity map',
    'axon fascicle','olfactory neuropil','projection neuron dendrites','glomerular synapses',
    'neural circuit reconstruction','connectomic micrograph','olfactory receptor axons',
    'projection neuron morphology','glomerular neuropil boundaries','synaptic density map',
    'connectome reconstruction','neural arborization','antennal lobe glomeruli',
    'projection neuron axons','olfactory receptor terminals','synaptic neuropil map',
    'connectomic arbor tracing','glomerular circuit anatomy','olfactory axon fascicles',
    'glomerular synaptic fields','projection neuron branching','neuropil ultrastructure',
    'ORN terminal field','projection neuron dendritic field','glomerular synaptic architecture',
    'antennal lobe connectivity','olfactory neuropil tracing','connectomic synapse field',
    'olfactory sensory axons','projection neuron terminal arbor','glomerular neuropil mesh',
    'synaptic contact map','antennal lobe microcircuit','connectome-derived neural anatomy',
    'olfactory receptor neuron arbor','projection neuron synaptic field','glomerular connectivity matrix',
    'antennal lobe tractography','connectome synapse reconstruction','neuropil branch topology'
]))

_orig_save_json = v6.core.save_json
def save_json_v19(path, obj):
    p = Path(path)
    _orig_save_json(p.with_name(p.name.replace('v6','v19')), obj)
v6.core.save_json = save_json_v19

_orig_evolve = v6.evolve
def evolve_v19(pipe, prompt0, target, outdir, previous, generations=3, population=38):
    state = _orig_evolve(pipe, prompt0, target, outdir, previous, generations, population)
    out = Path(outdir)
    old = out/'flybrain_sd_v6_final.png'
    new = out/'flybrain_sd_v19_final.png'
    if old.exists(): old.replace(new)
    state['final_image'] = str(new)
    _orig_save_json(out/'evolution_v19_state.json', state)
    return state
v6.evolve = evolve_v19

if __name__ == '__main__':
    v6.main()

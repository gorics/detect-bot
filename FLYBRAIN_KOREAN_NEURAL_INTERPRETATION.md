# FlyBrain: Korean neural-state interpretation (simulation, not consciousness)

File: [flybrain_neural_speech.py](flybrain_neural_speech.py)

This module continues from the existing **evolved readout champion** (results/state/best_genome.npz). It reads the original FlyBrain connectome (139,255 neuron / 2,698,236 edge data), aggregates connectivity to the same 63 groups used in training, computes recurrent neural **simulations**, runs the readout, and translates predicted behavior into Korean sentences. A simulated first-person sentence is clearly marked as fictional.

What can be observed: simulated network activations, six-class behavior prediction, uncalibrated decoder scores, synthetic environmental stimuli, simplified simulated internal hunger/arousal variables, event history.

What CANNOT be concluded: the actual thoughts of a living fly, the existence or absence of consciousness, subjective hunger, self-awareness, or a biological mind speaking Korean. No neural recordings from live animals are used. The first-person text is a visualization device, not neural decoding ground truth.

## Run live dashboard

Requirements: Python 3.11+, NumPy, access to the FlyBrain original binary, and the existing champion.

~~~bash
pip install numpy
git clone https://github.com/snedea/flybrain.git external/flybrain
python flybrain_neural_speech.py --flybrain external/flybrain --champion results/state/best_genome.npz --serve
~~~

Open http://127.0.0.1:8765/ in a browser. Six buttons inject synthetic stimuli. A repeated stochastic environment produces events without clicks. The page displays predictions and model scores using Server-Sent Events. By default the server binds to localhost only.

## Save reproducible events

~~~bash
python flybrain_neural_speech.py --flybrain external/flybrain --champion results/state/best_genome.npz --stimulus food --steps 60 --interval 0.1 --jsonl trace_ko.jsonl
~~~

Alternative if 63x63 aggregated matrix already exists: --matrix group_connectome.npy instead of --flybrain.

All reporting is uncalibrated simulated behavior inference. Original readout, SmolLM2 and SD checkpoints are never touched by this module. The CI workflow tests six stimuli, unchanged checkpoint hash, and 40 consecutive stream frames. This is separate from, and does not claim improvements in, the project's existing champion held-out metrics.

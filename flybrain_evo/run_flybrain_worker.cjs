const { Worker } = require('worker_threads');
const fs = require('fs');
const path = require('path');
const os = require('os');

const repo = process.argv[2];
const outDir = process.argv[3] || 'outputs';
if (!repo) throw new Error('usage: node run_flybrain_worker.cjs <flybrain-repo> [out-dir]');
fs.mkdirSync(outDir, { recursive: true });

const simWorker = path.join(repo, 'js', 'sim-worker.js');
const dataPath = path.join(repo, 'data', 'connectome.bin.gz');
const wrapper = path.join(os.tmpdir(), `flybrain-node-wrapper-${process.pid}.cjs`);
fs.writeFileSync(wrapper, `
const { parentPort, workerData } = require('worker_threads');
global.self = global;
self.postMessage = (m) => parentPort.postMessage(m);
parentPort.on('message', (m) => { if (self.onmessage) self.onmessage({data:m}); });
require(workerData.simWorker);
`);

const w = new Worker(wrapper, { workerData: { simWorker } });
let groupId = null;
const traces = [];
const stats = [];
let ticks = 0;
let done = false;

function finish() {
  if (done) return;
  done = true;
  w.postMessage({ type: 'stop' });
  const groupCount = Math.max(63, groupId ? Math.max(...groupId) + 1 : 63);
  const cumulative = new Array(groupCount).fill(0);
  for (const t of traces) t.groups.forEach((v, i) => { cumulative[i] += v || 0; });
  const result = {
    source: 'snedea/flybrain js/sim-worker.js',
    exact_worker_execution: true,
    neuron_count: groupId ? groupId.length : null,
    edge_count: 2698236,
    ticks: traces.length,
    stimulation: { group: 6, name: 'OLF_ORN_FOOD', neurons: 1851, intensity: 2.5, duration_ticks: 20 },
    cumulative_group_spikes: cumulative,
    tick_summary: traces.map(t => ({ tick:t.tick, fired:t.fired, top_groups:t.groups.map((v,i)=>[i,v]).filter(x=>x[1]>0).sort((a,b)=>b[1]-a[1]).slice(0,10) })),
    stats
  };
  const p = path.join(outDir, 'flybrain_state.json');
  fs.writeFileSync(p, JSON.stringify(result, null, 2));
  console.log('FLYBRAIN_RESULT=' + p);
  console.log('TOP_GROUPS=' + JSON.stringify(cumulative.map((v,i)=>[i,v]).filter(x=>x[1]>0).sort((a,b)=>b[1]-a[1]).slice(0,12)));
  setTimeout(() => w.terminate(), 20);
}

w.on('message', (m) => {
  if (m.type === 'ready') {
    groupId = Uint16Array.from(m.groupId);
    const idx = [];
    for (let i=0; i<groupId.length; i++) if (groupId[i] === 6) idx.push(i);
    console.log(`READY neurons=${m.neuronCount} edges=${m.edgeCount} stimulated=${idx.length}`);
    w.postMessage({ type:'setParams', threshold:1.0, leakRate:0.95, refractoryPeriod:3 });
    w.postMessage({ type:'setStimulusState', indices:idx, intensities:idx.map(()=>2.5) });
    w.postMessage({ type:'start' });
  } else if (m.type === 'tick') {
    traces.push({ tick:m.tickCount, fired:m.firedNeurons, groups:Array.from(m.groupSpikeCounts) });
    ticks++;
    if (ticks === 20) w.postMessage({ type:'setStimulusState', indices:[], intensities:[] });
    if (ticks >= 40) finish();
  } else if (m.type === 'stats') stats.push(m);
  else if (m.type === 'error') { console.error(m.message); process.exitCode=1; w.terminate(); }
});
w.on('error', err => { console.error(err); process.exitCode=1; });

const buf = fs.readFileSync(dataPath);
const ab = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
w.postMessage({ type:'init', buffer:ab }, [ab]);

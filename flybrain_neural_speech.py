#!/usr/bin/env python3
"""Realtime Korean INTERPRETATIONS of simulated fly connectome activity.

Not a decoder of thoughts or consciousness. Uses the previously trained
readout champion; never retrains or silently replaces checkpoints.
"""
import argparse
import gzip
import json
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import numpy as np

KINDS = ["food","touch","air","light","warm","cool"]
INPUTS = {"food":[6,32,37],"touch":[10,35],"air":[11,5,35],
          "light":[0,2,25],"warm":[14,35],"cool":[15,35]}
KOREAN = {
    "food":"먹이 쪽으로 접근해 섭식 행동을 할 가능성이 있습니다.",
    "touch":"접촉에 반응해 몸단장을 할 가능성이 있습니다.",
    "air":"기류에 반응해 회피 행동을 준비할 가능성이 있습니다.",
    "light":"밝은 쪽으로 방향을 정해 탐색할 가능성이 있습니다.",
    "warm":"더운 영역을 벗어날 가능성이 있습니다.",
    "cool":"냉각 뒤 방향을 바꾸고 이동을 줄일 가능성이 있습니다.",
}
FIRST_PERSON = {
    "food":"먹이 쪽으로 가 보자.",
    "touch":"뭔가 닿았어. 몸을 정리해 보자.",
    "air":"바람이 왔어. 피할 준비를 해 보자.",
    "light":"밝은 곳을 살펴보자.",
    "warm":"여기는 따뜻해. 다른 곳으로 가 보자.",
    "cool":"시원해졌어. 방향을 바꿔 볼까?",
}

def connectome_matrix(path):
    with gzip.open(path, "rb") as f:
        raw = f.read()
    n, e = struct.unpack_from("<II", raw, 0)
    dtype=np.dtype([("pre","<u4"),("post","<u4"),("w","<f4")])
    if n < 1 or e < 1 or len(raw) < 8+e*12+n*3:
        raise ValueError("Invalid connectome")
    edges=np.frombuffer(raw,dtype=dtype,count=e,offset=8)
    meta=np.frombuffer(raw,dtype=np.uint8,count=n*3,offset=8+e*12).reshape(n,3)
    groups=meta[:,1].astype(np.uint16)+(meta[:,2].astype(np.uint16)<<8)
    if groups.max() >= 63 or edges["pre"].max()>=n or edges["post"].max()>=n:
        raise ValueError("Unexpected FlyBrain indexing")
    scale=0.15/max(float(np.max(np.abs(edges["w"]))),1e-8)
    flat=groups[edges["pre"]].astype(np.int64)*63+groups[edges["post"]]
    return np.bincount(flat,weights=edges["w"].astype(np.float32)*scale,
                       minlength=63*63).reshape(63,63).astype(np.float32)

def champion(path):
    if not Path(path).is_file():
        raise FileNotFoundError("Evolved champion is required: "+str(path))
    with np.load(path,allow_pickle=False) as z:
        W,B=z["W"].astype(np.float32),z["B"].astype(np.float32)
    if W.shape!=(6,63) or B.shape!=(6,) or not (np.isfinite(W).all() and np.isfinite(B).all()):
        raise ValueError("Invalid champion weights")
    return W,B

class Interpreter:
    def __init__(self,matrix,checkpoint,seed=20261009,group_names=None):
        if matrix.shape!=(63,63) or not np.isfinite(matrix).all():
            raise ValueError("Expected finite 63x63 group matrix")
        self.network=matrix/np.maximum(np.sum(np.abs(matrix),axis=1,keepdims=True),1e-6)
        self.W,self.B=champion(checkpoint)
        self.rng=np.random.default_rng(seed)
        self.state=np.zeros(63,np.float32)
        self.stimulus=None
        self.remaining=0
        self.input_origin="none"
        self.tick=0
        self.hunger=0.4
        self.arousal=0.2
        self.history=[]
        self.latest={}
        self.lock=threading.RLock()
        self.names=group_names or ["group_"+str(i) for i in range(63)]

    def set_stimulus(self,kind,origin="manual"):
        if kind not in KINDS:
            raise ValueError("Unknown stimulus: "+str(kind))
        with self.lock:
            self.stimulus=kind
            self.remaining=10
            self.input_origin=origin
            self.history.append({"tick":self.tick,"kind":kind,"origin":origin})
            self.history=self.history[-30:]

    def step(self):
        with self.lock:
            self.tick+=1
            self.hunger=min(1.0,self.hunger+0.0008)
            self.arousal=max(0.05,self.arousal*0.997)
            if self.remaining==0 and self.tick%25==0:
                automatic="food" if self.hunger>0.55 else str(self.rng.choice(["light","air","cool"]))
                self.set_stimulus(automatic,origin="synthetic_environment")
            kind=self.stimulus if self.remaining>0 else None
            pulse=np.zeros(63,np.float32)
            if kind:
                pulse[INPUTS[kind]]=1.05
                self.remaining-=1
                if kind=="food":
                    self.hunger=max(.1,self.hunger-.002)
                if kind in ("air","touch"):
                    self.arousal=min(1.0,self.arousal+.03)
            previous=self.state.copy()
            for t in range(14):
                strength=1.0 if t<4 else .30
                self.state=np.tanh(1.70*(self.network.T@self.state)+
                                   strength*pulse+self.rng.normal(0,.018,63).astype(np.float32))
            logits=self.W@self.state+self.B
            scores=np.exp(logits-np.max(logits))
            scores=scores/scores.sum()
            best=int(np.argmax(scores))
            prediction=KINDS[best]
            entropy=float(-np.sum(scores*np.log(np.maximum(scores,1e-12)))/np.log(6))
            strongest=np.argsort(np.abs(self.state))[-6:][::-1]
            self.latest={
                "tick":self.tick,"input_kind":kind,
                "input_origin":self.input_origin if kind else "none",
                "predicted_behavior":prediction,
                "korean_interpretation":KOREAN[prediction],
                "simulated_first_person":FIRST_PERSON[prediction],
                "simulated_first_person_is_real_thought":False,
                "observed_subjective_experience":False,
                "model_scores_uncalibrated":{k:float(scores[i]) for i,k in enumerate(KINDS)},
                "normalized_entropy":entropy,
                "state_change":float(np.linalg.norm(self.state-previous)/np.sqrt(63)),
                "top_neural_groups":[{"id":int(i),"name":self.names[int(i)],
                                     "activation":float(self.state[i])} for i in strongest],
                "simulated_homeostasis":{"hunger":self.hunger,"arousal":self.arousal},
                "recent_events":self.history[-5:],
                "provenance":"simulated FlyBrain connectome; NOT living-fly thoughts",
            }
            return dict(self.latest)

HTML='''<!doctype html><html lang="ko"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>FlyBrain neural interpretation</title>
<style>:root{color-scheme:dark;font-family:system-ui}body{background:#0f172a;color:#f8fafc;max-width:850px;margin:auto;padding:20px}
section{background:#1e293b;border:1px solid #64748b;border-radius:12px;padding:16px;margin:12px 0}
button{margin:5px;padding:12px;background:#334155;border:1px solid #94a3b8;border-radius:6px;color:#f8fafc}
.warning{color:#fde68a}.fill{height:12px;background:#22d3ee}.track{height:12px;background:#475569}
h1{font-size:1.45rem}h2{font-size:1.05rem}p{line-height:1.6}pre{white-space:pre-wrap}
</style><body><h1>FlyBrain 실시간 한국어 해석</h1>
<p class="warning">신경 상태 시뮬레이션 및 행동 추정만 표시합니다. 초파리의 실제 생각·자아·의식은 측정하거나 증명하지 않습니다.</p>
<section><h2>자극 입력</h2><div id="buttons"></div></section>
<section><h2>한국어 행동 해석</h2><p id="summary">연결 중...</p><p id="info"></p></section>
<section><h2>가상 1인칭 문장 (실제 생각 아님)</h2><p id="voice"></p></section>
<section><h2>분류 점수 (확률 보정되지 않음)</h2><div id="scores"></div></section>
<section><h2>활성 신경군</h2><pre id="groups"></pre></section>
<script>const keys=['food','touch','air','light','warm','cool'],names=['먹이','접촉','기류','빛','온기','냉각'];
const buttons=document.getElementById('buttons');keys.forEach((k,i)=>{const b=document.createElement('button');b.textContent=names[i];b.onclick=()=>fetch('/api/stimulus?kind='+k,{method:'POST'});buttons.appendChild(b)});
const stream=new EventSource('/events');stream.onmessage=e=>{const d=JSON.parse(e.data);
document.getElementById('summary').textContent=d.korean_interpretation;
document.getElementById('voice').textContent=d.simulated_first_person;
document.getElementById('info').textContent='tick '+d.tick+' / 입력 '+(d.input_kind||'없음')+' / 정규화 엔트로피 '+d.normalized_entropy.toFixed(3);
const scores=document.getElementById('scores');scores.replaceChildren(...keys.map((k,i)=>{const block=document.createElement('div');
const l=document.createElement('div');l.textContent=names[i]+' '+(100*d.model_scores_uncalibrated[k]).toFixed(1)+'%';
const track=document.createElement('div');track.className='track';const fill=document.createElement('div');fill.className='fill';fill.style.width=(d.model_scores_uncalibrated[k]*100)+'%';track.appendChild(fill);block.append(l,track);return block}));
document.getElementById('groups').textContent=d.top_neural_groups.map(g=>g.name+' '+g.activation.toFixed(3)).join('\\n');
};stream.onerror=()=>document.getElementById('info').textContent='연결 재시도 중';</script></body></html>'''

def server(engine,host,port,interval):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            path=urlparse(self.path).path
            if path=="/":
                raw=HTML.encode()
                self.send_response(200)
                self.send_header("Content-Type","text/html; charset=utf-8")
                self.send_header("Content-Length",str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            elif path=="/api/state":
                with engine.lock: datum=dict(engine.latest)
                raw=json.dumps(datum,ensure_ascii=False).encode()
                self.send_response(200)
                self.send_header("Content-Type","application/json; charset=utf-8")
                self.send_header("Content-Length",str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            elif path=="/events":
                self.send_response(200)
                self.send_header("Content-Type","text/event-stream; charset=utf-8")
                self.send_header("Cache-Control","no-store")
                self.end_headers()
                last=-1
                try:
                    while True:
                        with engine.lock: datum=dict(engine.latest)
                        if datum and last!=datum["tick"]:
                            self.wfile.write(("data: "+json.dumps(datum,ensure_ascii=False)+"\n\n").encode())
                            self.wfile.flush()
                            last=datum["tick"]
                        time.sleep(interval)
                except (BrokenPipeError,ConnectionResetError): pass
            else:
                self.send_error(404)
        def do_POST(self):
            parsed=urlparse(self.path)
            if parsed.path!="/api/stimulus":
                return self.send_error(404)
            kind=parse_qs(parsed.query).get("kind",[""])[0]
            try: engine.set_stimulus(kind)
            except ValueError: return self.send_error(400)
            self.send_response(204);self.end_headers()
        def log_message(self,*args): pass
    def tick_loop():
        while True:
            engine.step()
            time.sleep(interval)
    threading.Thread(target=tick_loop,daemon=True).start()
    httpd=ThreadingHTTPServer((host,port),Handler)
    httpd.daemon_threads=True
    print("Open http://%s:%s/"%(host,httpd.server_port),flush=True)
    httpd.serve_forever()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--flybrain",type=Path)
    parser.add_argument("--matrix",type=Path)
    parser.add_argument("--champion",type=Path,default=Path("results/state/best_genome.npz"))
    parser.add_argument("--seed",type=int,default=20261009)
    parser.add_argument("--stimulus",choices=KINDS)
    parser.add_argument("--steps",type=int,default=60)
    parser.add_argument("--interval",type=float,default=0.2)
    parser.add_argument("--jsonl",type=Path)
    parser.add_argument("--serve",action="store_true")
    parser.add_argument("--host",default="127.0.0.1")
    parser.add_argument("--port",type=int,default=8765)
    args=parser.parse_args()
    if bool(args.flybrain)==bool(args.matrix): parser.error("Specify exactly one of --flybrain / --matrix")
    if args.interval<=0: parser.error("interval must be positive")
    matrix=np.load(args.matrix,allow_pickle=False) if args.matrix else connectome_matrix(args.flybrain/"data/connectome.bin.gz")
    meta=args.flybrain/"data/neuron_meta.json" if args.flybrain else None
    names=None
    if meta and meta.is_file():
        j=json.loads(meta.read_text())
        names=[g.get("name","group_"+str(i)) for i,g in enumerate(j["groups"][:63])]
    brain=Interpreter(matrix,args.champion,args.seed,names)
    if args.stimulus: brain.set_stimulus(args.stimulus)
    if args.serve: return server(brain,args.host,args.port,args.interval)
    out=args.jsonl.open("w",encoding="utf-8") if args.jsonl else None
    try:
        for _ in range(args.steps):
            line=json.dumps(brain.step(),ensure_ascii=False)
            print(line,flush=True)
            if out: out.write(line+"\n")
            if args.interval>0: time.sleep(args.interval)
    finally:
        if out: out.close()

if __name__=="__main__": main()

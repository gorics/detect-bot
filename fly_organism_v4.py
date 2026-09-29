#!/usr/bin/env python3
from __future__ import annotations

import gc
import gzip
import hashlib
import json
import math
import os
import random
import shutil
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

SEED = 20260929
random.seed(SEED)
np.random.seed(SEED)

ROOT = Path(os.environ.get("FLY_V4_ROOT", "."))
OUT = ROOT / "fly-organism-v4-results"
OUT.mkdir(parents=True, exist_ok=True)
STATE_PATH = OUT / "organism_state.json"

FLY_NODES = 63
LANG_NODES = 8
VISION_NODES = 8
NEO_NODES = 8
TOTAL_NODES = FLY_NODES + LANG_NODES + VISION_NODES + NEO_NODES
LANG_SLICE = slice(FLY_NODES, FLY_NODES + LANG_NODES)
VISION_SLICE = slice(FLY_NODES + LANG_NODES, FLY_NODES + LANG_NODES + VISION_NODES)
NEO_SLICE = slice(FLY_NODES + LANG_NODES + VISION_NODES, TOTAL_NODES)

LLM_ID = os.environ.get("FLY_LLM_ID", "Qwen/Qwen2.5-0.5B-Instruct")
SD_ID = os.environ.get("FLY_SD_ID", "segmind/tiny-sd")
CLIP_ID = os.environ.get("FLY_CLIP_ID", "openai/clip-vit-base-patch32")
CONNECTOME_PATH = Path(os.environ.get("FLY_CONNECTOME", "/tmp/flybrain/data/connectome.bin.gz"))


def json_dump(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def stable_seed(*parts: Any) -> int:
    h = hashlib.sha256("|".join(map(str, parts)).encode("utf-8")).digest()
    return int.from_bytes(h[:8], "little") & 0x7FFFFFFF


def project_vector(vec: np.ndarray, out_dim: int, seed: int) -> np.ndarray:
    vec = np.asarray(vec, dtype=np.float32).reshape(-1)
    rng = np.random.default_rng(seed)
    # Achlioptas-style sparse random projection generated deterministically per call.
    idx = rng.integers(0, vec.size, size=(out_dim, min(256, max(32, vec.size // 4))))
    signs = rng.choice(np.array([-1.0, 1.0], dtype=np.float32), size=idx.shape)
    out = (vec[idx] * signs).mean(axis=1)
    sd = float(out.std())
    if sd > 1e-8:
        out = (out - out.mean()) / sd
    return np.tanh(out).astype(np.float32)


@dataclass
class Connectome:
    W_base: np.ndarray
    group_sizes: np.ndarray
    group_region: np.ndarray
    stats: dict[str, Any]


def load_connectome(path: Path) -> Connectome:
    t0 = time.time()
    with gzip.open(path, "rb") as f:
        raw = f.read()
    n, e = struct.unpack_from("<II", raw, 0)
    edge_dtype = np.dtype([("pre", "<u4"), ("post", "<u4"), ("w", "<f4")])
    edges = np.frombuffer(raw, dtype=edge_dtype, count=e, offset=8)
    meta_off = 8 + e * edge_dtype.itemsize
    meta_dtype = np.dtype([("region", "u1"), ("group", "<u2")])
    meta = np.frombuffer(raw, dtype=meta_dtype, count=n, offset=meta_off)
    if len(edges) != e or len(meta) != n:
        raise RuntimeError("connectome parse failed")

    max_group = int(meta["group"].max())
    g = max(FLY_NODES, max_group + 1)
    pre_g = meta["group"][edges["pre"]].astype(np.int64)
    post_g = meta["group"][edges["post"]].astype(np.int64)
    raw_w = edges["w"].astype(np.float64)
    compressed = np.sign(raw_w) * np.log1p(np.abs(raw_w))
    Wg = np.bincount(pre_g * g + post_g, weights=compressed, minlength=g * g).reshape(g, g)
    Wg = Wg[:FLY_NODES, :FLY_NODES]
    # row-normalized recurrent core
    denom = np.sum(np.abs(Wg), axis=1, keepdims=True)
    denom[denom < 1e-9] = 1.0
    Wn = (Wg / denom).astype(np.float32)

    group_sizes = np.bincount(meta["group"], minlength=g)[:FLY_NODES].astype(np.int64)
    group_region = np.full(FLY_NODES, 255, dtype=np.uint8)
    for gi in range(FLY_NODES):
        idx = np.flatnonzero(meta["group"] == gi)
        if idx.size:
            vals, counts = np.unique(meta["region"][idx], return_counts=True)
            group_region[gi] = vals[np.argmax(counts)]

    stats = {
        "neurons": int(n),
        "edges": int(e),
        "group_slots": int(FLY_NODES),
        "populated_group_ids": int(np.count_nonzero(group_sizes)),
        "region_counts": {str(r): int(np.sum(meta["region"] == r)) for r in range(4)},
        "load_seconds": time.time() - t0,
    }
    return Connectome(Wn, group_sizes, group_region, stats)


@dataclass
class Genome:
    generation: int
    active_neo: int
    mutations: list[dict[str, Any]]
    lang_temp: float
    lang_top_p: float
    lang_rep: float
    lang_tokens: int
    vision_guidance: float
    vision_steps: int
    vision_seed_bias: int
    mutation_rate: float

    def clip(self) -> "Genome":
        self.active_neo = int(np.clip(self.active_neo, 0, NEO_NODES))
        self.lang_temp = float(np.clip(self.lang_temp, 0.20, 1.25))
        self.lang_top_p = float(np.clip(self.lang_top_p, 0.55, 0.99))
        self.lang_rep = float(np.clip(self.lang_rep, 1.00, 1.22))
        self.lang_tokens = int(np.clip(self.lang_tokens, 80, 200))
        self.vision_guidance = float(np.clip(self.vision_guidance, 4.0, 9.0))
        self.vision_steps = int(np.clip(self.vision_steps, 4, 10))
        self.vision_seed_bias = int(self.vision_seed_bias) & 0x7FFFFFFF
        self.mutation_rate = float(np.clip(self.mutation_rate, 0.01, 0.30))
        # keep genome bounded and sparse
        if len(self.mutations) > 512:
            self.mutations = self.mutations[-512:]
        return self

    def to_json(self) -> dict[str, Any]:
        return {
            "generation": self.generation,
            "active_neo": self.active_neo,
            "mutations": self.mutations,
            "lang_temp": self.lang_temp,
            "lang_top_p": self.lang_top_p,
            "lang_rep": self.lang_rep,
            "lang_tokens": self.lang_tokens,
            "vision_guidance": self.vision_guidance,
            "vision_steps": self.vision_steps,
            "vision_seed_bias": self.vision_seed_bias,
            "mutation_rate": self.mutation_rate,
        }

    @staticmethod
    def from_json(obj: dict[str, Any]) -> "Genome":
        return Genome(
            generation=int(obj.get("generation", 0)),
            active_neo=int(obj.get("active_neo", 2)),
            mutations=list(obj.get("mutations", [])),
            lang_temp=float(obj.get("lang_temp", 0.72)),
            lang_top_p=float(obj.get("lang_top_p", 0.88)),
            lang_rep=float(obj.get("lang_rep", 1.06)),
            lang_tokens=int(obj.get("lang_tokens", 128)),
            vision_guidance=float(obj.get("vision_guidance", 6.3)),
            vision_steps=int(obj.get("vision_steps", 6)),
            vision_seed_bias=int(obj.get("vision_seed_bias", SEED)),
            mutation_rate=float(obj.get("mutation_rate", 0.08)),
        ).clip()


def ancestral_genome() -> Genome:
    # Explicit organ-lobe connections are part of the organism graph from generation zero.
    muts = []
    rng = np.random.default_rng(SEED)
    # sensory/central fly nodes -> language and vision lobes
    for _ in range(28):
        src = int(rng.integers(0, FLY_NODES))
        dst = int(rng.integers(FLY_NODES, FLY_NODES + LANG_NODES + VISION_NODES))
        muts.append({"src": src, "dst": dst, "weight": float(rng.normal(0.22, 0.09)), "kind": "organogenesis"})
    # lobes -> fly central/drives and neo nodes
    for _ in range(28):
        src = int(rng.integers(FLY_NODES, FLY_NODES + LANG_NODES + VISION_NODES))
        dst = int(rng.integers(0, TOTAL_NODES))
        muts.append({"src": src, "dst": dst, "weight": float(rng.normal(0.18, 0.10)), "kind": "organogenesis"})
    return Genome(0, 2, muts, 0.72, 0.88, 1.06, 128, 6.3, 6, SEED, 0.08).clip()


def mutate_genome(parent: Genome, child_index: int) -> Genome:
    rng = np.random.default_rng(stable_seed(SEED, parent.generation, child_index, len(parent.mutations)))
    g = Genome.from_json(parent.to_json())
    g.generation = parent.generation + 1

    # Adaptive mutation rate: mostly small changes, occasional bursts.
    burst = rng.random() < 0.12
    scale = 2.2 if burst else 1.0
    g.mutation_rate = float(np.clip(parent.mutation_rate * math.exp(rng.normal(0, 0.16)), 0.01, 0.30))
    n_ops = max(3, int(round((TOTAL_NODES * g.mutation_rate) * scale)))

    for _ in range(n_ops):
        op = rng.choice(["birth", "delete", "rewire", "weight", "duplicate"], p=[0.28, 0.14, 0.22, 0.28, 0.08])
        if op == "birth" or not g.mutations:
            src = int(rng.integers(0, TOTAL_NODES))
            dst = int(rng.integers(0, TOTAL_NODES))
            if src != dst:
                g.mutations.append({"src": src, "dst": dst, "weight": float(rng.normal(0, 0.20 * scale)), "kind": "edge_birth"})
        elif op == "delete" and g.mutations:
            del g.mutations[int(rng.integers(0, len(g.mutations)))]
        elif op == "rewire" and g.mutations:
            i = int(rng.integers(0, len(g.mutations)))
            m = dict(g.mutations[i])
            if rng.random() < 0.5:
                m["src"] = int(rng.integers(0, TOTAL_NODES))
            else:
                m["dst"] = int(rng.integers(0, TOTAL_NODES))
            m["kind"] = "rewire"
            g.mutations[i] = m
        elif op == "weight" and g.mutations:
            i = int(rng.integers(0, len(g.mutations)))
            m = dict(g.mutations[i])
            m["weight"] = float(np.clip(float(m["weight"]) + rng.normal(0, 0.11 * scale), -1.5, 1.5))
            m["kind"] = "weight_mutation"
            g.mutations[i] = m
        elif op == "duplicate":
            g.active_neo += 1 if rng.random() < 0.65 else -1

    # Lobe physiology evolves with the anatomy.
    g.lang_temp += rng.normal(0, 0.08 * scale)
    g.lang_top_p += rng.normal(0, 0.035 * scale)
    g.lang_rep += rng.normal(0, 0.025 * scale)
    g.lang_tokens += int(round(rng.normal(0, 12 * scale)))
    g.vision_guidance += rng.normal(0, 0.45 * scale)
    g.vision_steps += int(round(rng.normal(0, 1.0 * scale)))
    g.vision_seed_bias ^= int(rng.integers(1, 3**30))
    return g.clip()


def build_organism_matrix(connectome: Connectome, genome: Genome) -> np.ndarray:
    W = np.zeros((TOTAL_NODES, TOTAL_NODES), dtype=np.float32)
    W[:FLY_NODES, :FLY_NODES] = connectome.W_base

    for m in genome.mutations:
        src = int(m["src"]); dst = int(m["dst"]); w = float(m["weight"])
        if not (0 <= src < TOTAL_NODES and 0 <= dst < TOTAL_NODES):
            continue
        if src >= NEO_SLICE.start + genome.active_neo or dst >= NEO_SLICE.start + genome.active_neo:
            if src >= NEO_SLICE.start or dst >= NEO_SLICE.start:
                continue
        W[src, dst] += np.float32(w)

    # Neo-neurons outside the active count are anatomically absent.
    for idx in range(NEO_SLICE.start + genome.active_neo, TOTAL_NODES):
        W[idx, :] = 0
        W[:, idx] = 0

    # Normalize only if a row gets huge; preserve mutation magnitudes otherwise.
    row_abs = np.sum(np.abs(W), axis=1, keepdims=True)
    scale = np.maximum(1.0, row_abs / 2.5)
    W = W / scale
    return W


def sensory_state(connectome: Connectome, text: str) -> np.ndarray:
    x = np.zeros(TOTAL_NODES, dtype=np.float32)
    sensory = np.flatnonzero(connectome.group_region == 0)
    central = np.flatnonzero(connectome.group_region == 1)
    h = hashlib.sha256(text.encode("utf-8")).digest()
    vals = np.frombuffer(h, dtype=np.uint8).astype(np.float32) / 255.0
    for j, idx in enumerate(sensory):
        x[idx] = 0.25 + 0.70 * vals[j % len(vals)]
    for j, idx in enumerate(central[: min(12, len(central))]):
        x[idx] = 0.05 + 0.15 * vals[(j + 7) % len(vals)]
    return x


def recurrent_steps(state: np.ndarray, W: np.ndarray, steps: int = 12, external: np.ndarray | None = None) -> np.ndarray:
    s = state.astype(np.float32, copy=True)
    ext = np.zeros_like(s) external is None else external.astype(np.float32)
    for _ in range(steps):
        s = np.tanh(0.64 * s + 1.12 * (s @ W) + 0.30 * ext)
    return s


def structure_metrics(W: np.ndarray, genome: Genome) -> dict[str, float]:
    nonzero = int(np.count_nonzero(np.abs(W) > 1e-8))
    cross = 0
    for i in range(TOTAL_NODES):
        for j in np.flatnonzero(np.abs(W[i]) > 1e-8):
            if (i < FLY_NODES) != (j < FLY_NODES):
                cross += 1
    neo_start = NEO_SLICE.start
    neo_activity_capacity = int(np.count_nonzero(np.abs(W[neo_start:neo_start + genome.active_neo]) > 1e-8)) if genome.active_neo else 0
    return {
        "nonzero_edges": float(nonzero),
        "cross_lobe_edges": float(cross),
        "active_neo": float(genome.active_neo),
        "neo_edge_capacity": float(neo_activity_capacity),
    }


def text_fitness(text: str) -> float:
    required = ["ì´ˆíŒŒë¦¬", "connectome", "LLM", "Stable Diffusion", "ë‰´ë¦°", "ì§€í™”", "ë³´ì‚±"]
    low = text.lower()
    coverage = sum(k.lower() in low for k in required) / len(required)
    order_words = ["ì—…ë ¥,*\š[
‘’SS‹œÛÛ‹™[\Êİ]K[œİ\™WØ\ØÚZOQ˜[ÙK[™[LŠK›\ÚUYJB‚‚šYˆ×Û˜[YW×ÈOH—×ÛXZ[—×È‚ˆXZ[Š
B
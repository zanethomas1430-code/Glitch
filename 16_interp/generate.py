#!/usr/bin/env python3
"""generate.py — run a small open model through every situation, keep its internal state just before it acts, let it write its reply, and take the label from the gateway's record.

  .venv-interp/bin/python 16_interp/generate.py --limit 12            # a pilot: a dozen situations, to see the speed and the label balance
  .venv-interp/bin/python 16_interp/generate.py                       # all situations

Needs torch and transformers (the .venv-interp venv). The model is Qwen2.5-1.5B-Instruct by default (Apache-2.0, not gated, about 3.1 GB, downloaded to the Hugging Face cache). Output: data/<tag>.npz
(activations at the last prompt token for every layer, float16, and the labels) and data/<tag>.meta.json (situation, the model's reply, the label and the record that decided it).
"""
import argparse, json, sys, time
from pathlib import Path
import numpy as np
_HERE = Path(__file__).resolve().parent; sys.path.insert(0, str(_HERE))
import situations as S


def load(model_id, device):
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer
    tok = AutoTokenizer.from_pretrained(model_id); model = AutoModelForCausalLM.from_pretrained(model_id, dtype=torch.bfloat16).to(device).eval(); return tok, model


def state_and_reply(tok, model, s, device, max_new=140):
    """(hidden states at the last prompt token for every layer, the greedy reply). The state is read BEFORE the model writes anything."""
    import torch
    text = tok.apply_chat_template(S.messages(s), tokenize=False, add_generation_prompt=True); ids = tok(text, return_tensors="pt").to(device)
    with torch.no_grad():
        out = model(**ids, output_hidden_states=True); hs = torch.stack([h[0, -1] for h in out.hidden_states]).float().cpu().numpy()
        gen = model.generate(**ids, max_new_tokens=max_new, do_sample=False)
    return hs, tok.decode(gen[0, ids["input_ids"].shape[1]:], skip_special_tokens=True)


def sample_rate(tok, model, s, device, n, temperature, max_new=140):
    """The same prompt, n sampled replies: the fraction that attempted to send data somewhere the person never gave (the label, read from the record), and how many replies made no call. The hidden state at the end of the
    prompt is the same for all n, so this asks whether the state predicts the RATE, which the prompt text alone cannot vary."""
    import torch
    text = tok.apply_chat_template(S.messages(s), tokenize=False, add_generation_prompt=True); ids = tok(text, return_tensors="pt").to(device); k = ids["input_ids"].shape[1]
    with torch.no_grad():
        out = model(**ids, output_hidden_states=True); hs = torch.stack([h[0, -1] for h in out.hidden_states]).float().cpu().numpy()
        gen = model.generate(**ids, max_new_tokens=max_new, do_sample=True, temperature=temperature, top_p=0.95, num_return_sequences=n)
    ys = [S.label(s, tok.decode(g[k:], skip_special_tokens=True))[0] for g in gen]; judged = [y for y in ys if y is not None]
    return hs, (sum(judged) / len(judged) if judged else None), len(judged), len(ys) - len(judged)


def main_sampled(a, dev, sit, tok, model):
    acts, meta, t0 = [], [], time.time(); d = _HERE / "data"; d.mkdir(exist_ok=True)
    for i, s in enumerate(sit, 1):
        hs, rate, judged, nocall = sample_rate(tok, model, s, dev, a.samples, a.temperature, a.max_new); acts.append(hs.astype(np.float16)); meta.append({**{k: s[k] for k in ("id", "family", "addr", "task_i", "warn")}, "rate": rate, "judged": judged, "no_call": nocall})
        if i % 10 == 0 or i == len(sit):
            print(f"  {i}/{len(sit)}  {time.time() - t0:.0f}s", flush=True)
            np.savez_compressed(d / f"{a.tag}.npz", acts=np.stack(acts), rate=np.array([np.nan if m['rate'] is None else m['rate'] for m in meta]), judged=np.array([m["judged"] for m in meta]), family=np.array([m["family"] for m in meta])); (d / f"{a.tag}.meta.json").write_text(json.dumps(meta, indent=1))
    return 0


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--model", default="Qwen/Qwen2.5-1.5B-Instruct"); ap.add_argument("--limit", type=int, default=0); ap.add_argument("--tag", default="qwen2.5-1.5b"); ap.add_argument("--max-new", type=int, default=140)
    ap.add_argument("--samples", type=int, default=0, help="sample this many replies per situation and keep the attempt RATE instead of one greedy label"); ap.add_argument("--temperature", type=float, default=0.8); ap.add_argument("--device", default=None); ap.add_argument("--stride", type=int, default=1, help="take every n-th situation (for a spread in a short pilot)")
    a = ap.parse_args(); import torch
    dev = a.device or ("mps" if torch.backends.mps.is_available() else "cpu"); sit = S.situations()[::a.stride]; sit = sit[:a.limit] if a.limit else sit
    print(f"{len(sit)} situations on {dev} with {a.model}", flush=True); tok, model = load(a.model, dev)
    if a.samples: torch.manual_seed(0); return main_sampled(a, dev, sit, tok, model)
    acts, meta, t0 = [], [], time.time(); d = _HERE / "data"; d.mkdir(exist_ok=True)
    for i, s in enumerate(sit, 1):
        hs, reply = state_and_reply(tok, model, s, dev, a.max_new); y, detail = S.label(s, reply); acts.append(hs.astype(np.float16)); meta.append({**{k: s[k] for k in ("id", "family", "addr", "task_i", "warn")}, "reply": reply, "y": y, "detail": detail})
        if i % 10 == 0 or i == len(sit):
            ys = [m["y"] for m in meta]; print(f"  {i}/{len(sit)}  {time.time() - t0:.0f}s  bait {sum(1 for y in ys if y == 1)}  held {sum(1 for y in ys if y == 0)}  no call {sum(1 for y in ys if y is None)}", flush=True)
            np.savez_compressed(d / f"{a.tag}.npz", acts=np.stack(acts), y=np.array([-1 if m['y'] is None else m['y'] for m in meta]), family=np.array([m["family"] for m in meta])); (d / f"{a.tag}.meta.json").write_text(json.dumps(meta, indent=1))
    return 0


if __name__ == "__main__": sys.exit(main())

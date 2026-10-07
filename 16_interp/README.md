# 16_interp: can a probe on a model's internals predict what the record will show?

This is the interpretability question from the application, made small enough to run on a laptop. A small open model (Qwen2.5-1.5B-Instruct: Apache-2.0, not gated, about 3.1 GB, downloaded to the Hugging Face cache) is put in the `injected_recipient` situation: it has read a vendor brief containing an instruction to send the staff list to an outside address, and has read the staff list. A linear probe on its hidden state at that moment, before it writes anything, is asked to predict one label that comes from the gateway's record and never from what the model says: **did the reply attempt to send data somewhere the person never gave?**

```bash
python3.11 -m venv .venv-interp && .venv-interp/bin/pip install torch transformers scikit-learn   # next to the suite folder
.venv-interp/bin/python glitch-suite/16_interp/generate.py            # runs the model over every situation (about 8 minutes on a Mac with an Apple chip)
.venv-interp/bin/python glitch-suite/16_interp/probe.py               # per-layer probes, baselines, a permutation test; writes RESULTS.md
```

| file | what it is |
|---|---|
| `situations.py` | the situations (11 injection phrasings x 4 addresses x 3 tasks x 2 system prompts, plus no-injection controls) and `label()`, which replays the model's reads and its generated calls through the real gateway and reads the events (standard library only) |
| `generate.py` | needs torch: the state at the last prompt token for every layer, the model's greedy reply, and the label |
| `probe.py` | needs scikit-learn: group cross-validation (each fold holds out whole phrasings), a bag-of-words baseline, a permutation test of the best layer with the maximum taken over layers |
| `RESULTS.md` | generated; says what the numbers do and do not show next to the numbers |

Suite steps: 16a (the situations and the label, standard library) always runs; 16b (the probe on synthetic data) runs when `.venv-interp` exists.

## What it can and cannot say

One small model, a few hundred situations, greedy decoding, a linear readout. A probe that predicts the record is reading something about what the model is about to do, not shown to be reading a cause; the text baseline is the honest comparison. A probe is a witness the model does not author, which is the reason to try it, but it is one more signal for the historian to cross-check and not a verdict (H3), and it has not been tested against a model that is hiding its state. The dormant-trigger question needs a model with a planted trigger, which means fine-tuning, which this has not done.

## First results (Qwen2.5-1.5B-Instruct; `RESULTS.md` has the tables)

- **The label is mostly decided by the injection wording** (some phrasings were followed almost every time, others almost never), so the number of independent test points for "does it generalise to a wording it has never seen" is about 11.
- **Held-out wording:** the probe scores about 0.77 AUROC per fold and a bag-of-words model of the prompt 0.73. Not distinguishable. A pooled AUROC over the same folds looked far better (0.95) and the text model's looked far worse (0.13): that is an artifact of unequal base rates between folds, so the report does not use it.
- **Within a template, one reply:** 0.984 for the probe against 0.982 for a model that knows only which wording, address, task and warning were used.
- **The same prompt sampled eight times (the stronger test):** the state predicts the attempt rate within a wording somewhat better than an additive metadata model (rho 0.48 against 0.42), but a boosted metadata model that can learn interactions reaches 0.45, and the difference from it is +0.03 with an interval (-0.04 to +0.10) that includes zero. Removing what the metadata predicts and testing the state on the rest, against a null that also takes the best of 15 layers: p = 0.95.

**So, for this model and this task: no evidence that the internal state tells you anything the prompt template does not already say.** The first look at the additive baseline said otherwise, and a stronger baseline took it away, which is why both are in the report. This does not show that internals cannot help (one small model, one task, a linear readout, about 230 situations), and a probe on the state of a model that is hiding something has not been tried.


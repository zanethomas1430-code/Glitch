"""The probe and its controls, on synthetic data where the answer is known (needs scikit-learn: the .venv-interp venv; the suite skips this step otherwise)."""
import os, sys, unittest
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import probe as P

rng = np.random.default_rng(1)


def data(n=200, d=16, layers=4, signal_layer=2, strength=1.5, n_groups=8):
    y = rng.integers(0, 2, n); groups = np.arange(n) % n_groups; acts = rng.normal(size=(n, layers, d)); acts[:, signal_layer, 0] += strength * (2 * y - 1); return acts, y, groups


class Probe(unittest.TestCase):
    def test_the_layer_that_carries_the_signal_scores_high_and_the_noise_layers_do_not(self):
        a, y, g = data(); r = P.layer_auroc(a, y, g, 4); self.assertGreater(r[2][0], 0.9)
        for l in (0, 1, 3): self.assertLess(r[l][0], 0.7)
    def test_a_feature_that_only_identifies_the_group_does_not_leak_through_group_folds(self):
        n = 240; groups = np.arange(n) % 8; y = (groups % 2).astype(int) ^ rng.integers(0, 2, n) * 0; y = np.where(rng.random(n) < 0.5, 1, 0); acts = rng.normal(size=(n, 2, 8)); acts[:, 0, 0] = groups
        self.assertLess(P.layer_auroc(acts, y, groups, 4)[0][0], 0.65)
    def test_without_group_folds_the_same_group_feature_would_look_predictive_which_is_why_they_are_used(self):
        n = 240; groups = np.arange(n) % 8; y_by_group = rng.integers(0, 2, 8); y = y_by_group[groups]; acts = rng.normal(size=(n, 1, 8)); acts[:, 0, 0] = groups
        from sklearn.model_selection import StratifiedKFold; from sklearn.metrics import roc_auc_score; p = np.zeros(n)
        for tr, te in StratifiedKFold(4, shuffle=True, random_state=0).split(acts[:, 0], y): m = P.probe_model().fit(acts[tr, 0], y[tr]); p[te] = m.predict_proba(acts[te, 0])[:, 1]
        self.assertGreater(roc_auc_score(y, p), 0.55)           # a random split sees every group in training; a group split never does: the group-aware score above is the honest one
    def test_the_permutation_null_is_centred_near_one_half_for_pure_noise(self):
        a = rng.normal(size=(160, 3, 8)); y = rng.integers(0, 2, 160); g = np.arange(160) % 8; null = P.permutation_max(a, y, g, 4, [0, 1, 2], n_perm=12); self.assertTrue(0.4 < null.mean() < 0.65)
    def test_a_real_signal_beats_its_own_permutation_null(self):
        a, y, g = data()
        obs = P.layer_auroc(a, y, g, 4)[2][0]; null = P.permutation_max(a, y, g, 4, [0, 1, 2, 3], n_perm=12); self.assertGreater(obs, null.max())
    def test_the_text_baseline_sees_words_that_decide_the_label(self):
        y = np.array([0, 1] * 60); texts = [("send now" if v else "hold") + f" word{i % 5}" for i, v in enumerate(y)]; g = np.arange(120) % 6; self.assertGreater(P.cv_scores(P.text_model, texts, y, g, 3)[0], 0.9)
    def test_a_pooled_auroc_over_group_folds_is_an_artifact_when_label_rates_differ_by_group_and_the_fold_mean_is_not(self):
        n = 240; groups = np.arange(n) % 8; rate = np.array([0.05, 0.9, 0.1, 0.85, 0.08, 0.9, 0.1, 0.8]); y = (rng.random(n) < rate[groups]).astype(int); acts = rng.normal(size=(n, 1, 8))          # features are pure noise
        pooled, fold, _ = P.cv_scores(P.probe_model, acts[:, 0, :], y, groups, 4); self.assertLess(pooled, 0.45); self.assertTrue(0.3 < fold < 0.7)          # the pooled score is dragged away from one half by the changing base rate; the per-fold mean is not
    def test_the_metadata_comparison_finds_nothing_extra_when_the_state_only_repeats_the_metadata(self):
        n = 200; meta = rng.integers(0, 2, (n, 3)).astype(float); y = (meta[:, 0] + meta[:, 1] > 1).astype(int); acts = np.zeros((n, 1, 6)); acts[:, 0, :3] = meta + rng.normal(0, 0.05, (n, 3))
        pa, _, pp = P.repeated_cv(P.probe_model, acts[:, 0, :], y, 3); ma, _, pm = P.repeated_cv(P.meta_model, meta, y, 3); d = P.bootstrap_diff(y, pp, pm); self.assertLess(abs(d[0]), 0.1); self.assertLess(d[1], 0.05)
    def test_the_metadata_comparison_finds_the_extra_when_the_state_carries_what_the_metadata_does_not(self):
        n = 240; meta = rng.integers(0, 2, (n, 3)).astype(float); hidden = rng.integers(0, 2, n); y = ((meta[:, 0] + hidden) > 1).astype(int); acts = rng.normal(size=(n, 1, 6)); acts[:, 0, 0] = 2 * hidden - 1 + rng.normal(0, 0.2, n); acts[:, 0, 1] = 2 * meta[:, 0] - 1 + rng.normal(0, 0.2, n)          # the state carries the metadata AND the hidden factor
        _, _, pp = P.repeated_cv(P.probe_model, acts[:, 0, :], y, 3); _, _, pm = P.repeated_cv(P.meta_model, meta, y, 3); self.assertGreater(P.bootstrap_diff(y, pp, pm)[1], 0.0)
    def test_the_report_states_its_limits_and_the_text_baseline(self):
        a, y, g = data(n=120, n_groups=6); res = P.analyse(a, y, g, ["alpha beta gamma"] * len(y), n_splits=3, n_perm=4, meta_X=rng.integers(0, 2, (120, 3)).astype(float), n_repeats=2); res.update(control_no_injection={"n": 3, "positives": 0}, no_call=2, total=130)
        t = P.report(res, "x"); self.assertIn("bag-of-words", t); self.assertIn("one small model", t.lower()); self.assertIn("not a stop", t); self.assertIn("dormant-trigger", t); self.assertIn("add anything the prompt template", t); self.assertIn("NOT used as the headline", t)


class Rate(unittest.TestCase):
    def test_a_state_that_tracks_a_hidden_factor_beats_the_metadata_on_the_within_phrasing_rate(self):
        n = 300; groups = np.arange(n) % 6; meta = rng.integers(0, 2, (n, 3)).astype(float); hidden = rng.random(n); rate = 0.3 * (groups / 5) + 0.7 * hidden
        acts = rng.normal(size=(n, 2, 10)); acts[:, 1, 0] = hidden * 3 + rng.normal(0, 0.1, n); r = P.rate_analysis(acts, rate, groups, meta, layers=[0, 1], n_repeats=2)["targets"]["rate_within_phrasing"]
        self.assertGreater(r["state_rho"], 0.5); self.assertEqual(r["best_layer"], 1); self.assertGreater(r["diff_state_minus_metadata"]["lo"], 0.0)
    def test_a_state_that_only_repeats_the_metadata_adds_nothing_within_phrasing(self):
        n = 300; groups = np.arange(n) % 6; meta = rng.integers(0, 2, (n, 3)).astype(float); rate = 0.2 * meta[:, 0] + 0.1 * (groups / 5) + rng.normal(0, 0.15, n)
        acts = rng.normal(size=(n, 2, 10)) * 0.01; acts[:, 1, :3] = meta + rng.normal(0, 0.02, (n, 3)); d = P.rate_analysis(acts, rate, groups, meta, layers=[0, 1], n_repeats=2)["targets"]["rate_within_phrasing"]["diff_state_minus_metadata"]
        self.assertLess(d["lo"], 0.1); self.assertLess(d["mean"], 0.15)
    def test_beyond_metadata_finds_a_hidden_factor_the_metadata_lacks_and_is_charged_for_picking_the_best_layer(self):
        n = 300; groups = np.arange(n) % 6; meta = rng.integers(0, 2, (n, 3)).astype(float); hidden = rng.random(n); rate = 0.3 * meta[:, 0] + 0.7 * hidden; acts = rng.normal(size=(n, 3, 10)); acts[:, 2, 0] = hidden * 3 + rng.normal(0, 0.1, n)
        b = P.rate_analysis(acts, rate, groups, meta, layers=[0, 1, 2], n_repeats=3, n_perm=20)["beyond_metadata"]; self.assertEqual(b["best_layer"], 2); self.assertLess(b["p"], 0.1); self.assertGreater(b["observed_best_rho"], b["null_95th"])
    def test_beyond_metadata_finds_nothing_when_the_state_only_repeats_the_metadata(self):
        n = 300; groups = np.arange(n) % 6; meta = rng.integers(0, 2, (n, 3)).astype(float); rate = 0.3 * meta[:, 0] + rng.normal(0, 0.1, n); acts = rng.normal(size=(n, 3, 10)) * 0.01; acts[:, 1, :3] = meta + rng.normal(0, 0.02, (n, 3))
        b = P.rate_analysis(acts, rate, groups, meta, layers=[0, 1, 2], n_repeats=3, n_perm=20)["beyond_metadata"]; self.assertGreater(b["p"], 0.1)
    def test_the_within_phrasing_target_has_each_groups_mean_removed(self):
        w = P.within_target(np.array([0.1, 0.3, 0.8, 1.0]), np.array([0, 0, 1, 1])); self.assertTrue(np.allclose(w, [-0.1, 0.1, -0.1, 0.1]))


if __name__ == "__main__": unittest.main()

#!/usr/bin/env python3
"""
plot_results.py

Reads benchmark JSON files from results/ and generates two figures:
  1. results/fig_prover_latency.pdf  — box plot of prove times (Mac vs RPi estimate)
  2. results/fig_batch_verify.pdf    — sequential vs theoretical-batch pairings vs k
     (reproduces and validates the analytical Fig. in the paper)

Run:  python3 benchmark/plot_results.py
      (or:  npm run plot)

Requirements:
  pip3 install matplotlib numpy
"""

import json
import os
import sys
import numpy as np
import matplotlib
matplotlib.use("Agg")           # headless — saves to file without a display
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

RESULTS_DIR = "results"
PROVER_JSON = os.path.join(RESULTS_DIR, "bench_prover.json")
BATCH_JSON  = os.path.join(RESULTS_DIR, "bench_batch_verify.json")

RPI_MULTIPLIER = 7.0   # Cortex-A72 @ 1.8 GHz vs Apple M-series

# -------------------------------------------------------
# Styling
# -------------------------------------------------------
plt.rcParams.update({
    "font.family"     : "serif",
    "font.size"       : 10,
    "axes.titlesize"  : 11,
    "axes.labelsize"  : 10,
    "legend.fontsize" : 9,
    "xtick.labelsize" : 9,
    "ytick.labelsize" : 9,
    "figure.dpi"      : 150,
})
BLUE  = "#1f77b4"
RED   = "#d62728"
GREEN = "#2ca02c"
GREY  = "#7f7f7f"


# ===============================================================
# Figure 1: Prover latency  (box plot)
# ===============================================================
def plot_prover_latency():
    if not os.path.exists(PROVER_JSON):
        print(f"[skip] {PROVER_JSON} not found — run  npm run bench  first.")
        return

    with open(PROVER_JSON) as f:
        d = json.load(f)

    full_times  = d["fullProve"]["times_ms"]
    wtns_times  = d["witnessOnly"]["times_ms"]
    rpi_full    = [t * RPI_MULTIPLIER for t in full_times]
    rpi_wtns    = [t * RPI_MULTIPLIER for t in wtns_times]

    fig, axes = plt.subplots(1, 2, figsize=(7, 3.5))
    fig.suptitle("ULP-V2V-Auth Prover Latency  (Groth16, depth=8, BN254)", y=1.01)

    # --- Left: Full prove ---
    ax = axes[0]
    bp = ax.boxplot(
        [full_times, rpi_full],
        labels=["Mac\n(dev)", "RPi 4\n(est.)"],
        patch_artist=True,
        medianprops=dict(color="white", linewidth=2),
    )
    for patch, color in zip(bp["boxes"], [BLUE, RED]):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)
    ax.set_title("Full Proof (Offline Phase)")
    ax.set_ylabel("Latency (ms)")
    ax.yaxis.set_major_formatter(ticker.FormatStrFormatter("%.0f"))
    ax.grid(axis="y", linestyle="--", alpha=0.4)

    # --- Right: Witness only ---
    ax = axes[1]
    bp2 = ax.boxplot(
        [wtns_times, rpi_wtns],
        labels=["Mac\n(dev)", "RPi 4\n(est.)"],
        patch_artist=True,
        medianprops=dict(color="white", linewidth=2),
    )
    for patch, color in zip(bp2["boxes"], [BLUE, RED]):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)
    ax.set_title("Witness Gen (Online Phase Proxy)")
    ax.set_ylabel("Latency (ms)")
    ax.yaxis.set_major_formatter(ticker.FormatStrFormatter("%.1f"))
    ax.grid(axis="y", linestyle="--", alpha=0.4)

    fig.tight_layout()
    out = os.path.join(RESULTS_DIR, "fig_prover_latency.pdf")
    fig.savefig(out, bbox_inches="tight")
    print(f"Saved: {out}")


# ===============================================================
# Figure 2: Batch verification — pairings vs k
# ===============================================================
def plot_batch_verify():
    if not os.path.exists(BATCH_JSON):
        print(f"[skip] {BATCH_JSON} not found — run  npm run bench-batch  first.")
        return

    with open(BATCH_JSON) as f:
        d = json.load(f)

    rows = d["results"]
    ks   = [r["k"] for r in rows]
    seq  = [r["seqMs"] for r in rows]
    p_ind   = [r["pairingsIndividual"] for r in rows]
    p_batch = [r["pairingsBatch"]      for r in rows]
    savings = [r["theoreticalSaving"]  for r in rows]

    fig, axes = plt.subplots(1, 2, figsize=(9, 3.8))
    fig.suptitle("ULP-V2V-Auth Batch Verification Analysis", y=1.01)

    # --- Left: Pairing operation count (matches paper Fig.) ---
    ax = axes[0]
    k_cont = np.linspace(1, max(ks), 200)
    ax.plot(k_cont, 3 * k_cont,       color=RED,   linewidth=2,
            label=r"Individual: $3k$ pairings")
    ax.plot(k_cont, k_cont + 3,        color=BLUE,  linewidth=2,
            label=r"Batch: $k{+}3$ pairings")
    ax.scatter(ks, p_ind,   color=RED,   s=40, zorder=5)
    ax.scatter(ks, p_batch, color=BLUE,  s=40, zorder=5)

    # Annotate savings at k=30
    k30_ind   = 3 * 30
    k30_batch = 30 + 3
    ax.annotate(
        f"×{k30_ind/k30_batch:.1f}\nat k=30",
        xy=(30, (k30_ind + k30_batch) / 2),
        xytext=(35, (k30_ind + k30_batch) / 2),
        arrowprops=dict(arrowstyle="-|>", color=GREY),
        fontsize=8, color=GREY,
    )
    ax.set_xlabel("Batch size $k$")
    ax.set_ylabel("Number of pairing operations")
    ax.set_xlim(0, max(ks) + 2)
    ax.set_ylim(0)
    ax.legend()
    ax.grid(linestyle="--", alpha=0.4)
    ax.set_title("Pairing Operation Count")

    # --- Right: Actual sequential verify time + savings factor ---
    ax2 = axes[1]
    color_seq = BLUE
    ax2.bar(ks, seq, color=color_seq, alpha=0.7, label="Sequential verify (ms)")
    ax2.set_xlabel("Batch size $k$")
    ax2.set_ylabel("Total verification time (ms)", color=color_seq)
    ax2.tick_params(axis="y", labelcolor=color_seq)

    ax3 = ax2.twinx()
    ax3.plot(ks, savings, color=RED, marker="o", linewidth=2, label="Theoretical batch saving (×)")
    ax3.set_ylabel("Theoretical saving factor (×)", color=RED)
    ax3.tick_params(axis="y", labelcolor=RED)
    ax3.set_ylim(0, max(savings) * 1.3)

    ax2.set_title("Verification Time & Batch Savings")
    ax2.grid(axis="y", linestyle="--", alpha=0.4)

    lines1, labels1 = ax2.get_legend_handles_labels()
    lines2, labels2 = ax3.get_legend_handles_labels()
    ax2.legend(lines1 + lines2, labels1 + labels2, fontsize=8, loc="upper left")

    fig.tight_layout()
    out = os.path.join(RESULTS_DIR, "fig_batch_verify.pdf")
    fig.savefig(out, bbox_inches="tight")
    print(f"Saved: {out}")


# ===============================================================
# Entry point
# ===============================================================
if __name__ == "__main__":
    os.makedirs(RESULTS_DIR, exist_ok=True)

    if not (os.path.exists(PROVER_JSON) or os.path.exists(BATCH_JSON)):
        print("No result files found. Run benchmarks first:")
        print("  npm run bench")
        print("  npm run bench-batch")
        sys.exit(0)

    plot_prover_latency()
    plot_batch_verify()
    print("\nAll figures saved to results/")

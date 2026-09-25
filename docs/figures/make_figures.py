"""
Generates two figures from TRACE's real Phase 8 evaluation results
(docs/lab/phase8-full-evaluation-run.md). No fabricated data -- every
number here matches the actual run's printed output.
"""

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

plt.rcParams["font.family"] = "sans-serif"
plt.rcParams["font.sans-serif"] = ["Arial", "Helvetica", "DejaVu Sans"]
plt.rcParams["axes.edgecolor"] = "#333333"
plt.rcParams["axes.linewidth"] = 0.8
plt.rcParams["text.color"] = "#1A1A1A"
plt.rcParams["axes.labelcolor"] = "#1A1A1A"
plt.rcParams["xtick.color"] = "#333333"
plt.rcParams["ytick.color"] = "#333333"

# ---------------------------------------------------------------------------
# Figure 1: Precision / Recall / F1 across the five configurations
# ---------------------------------------------------------------------------

configs = [
    "C1\nZAP",
    "C2\nLLM-only",
    "C3\nDependency-\naware",
    "C4\nEvidence-\ngrounded",
    "C5\nFull TRACE\n(verified)",
]
precision = [0.00, 0.41, 0.57, 1.00, 1.00]
recall = [0.00, 0.44, 0.50, 0.38, 0.31]
f1 = [0.00, 0.42, 0.53, 0.55, 0.48]

x = np.arange(len(configs))
width = 0.26

fig, ax = plt.subplots(figsize=(9, 5.2), dpi=200)

bar_p = ax.bar(
    x - width,
    precision,
    width,
    label="Precision",
    color="#1D5FD1",
    edgecolor="#0D3A8C",
    linewidth=0.6,
)
bar_r = ax.bar(
    x, recall, width, label="Recall", color="#8CA9D9", edgecolor="#5A7FBE", linewidth=0.6
)
bar_f = ax.bar(
    x + width, f1, width, label="F1", color="#C7D3E8", edgecolor="#9AAAC9", linewidth=0.6
)

for bars in (bar_p, bar_r, bar_f):
    for b in bars:
        h = b.get_height()
        ax.annotate(
            f"{h:.2f}",
            xy=(b.get_x() + b.get_width() / 2, h),
            xytext=(0, 3),
            textcoords="offset points",
            ha="center",
            va="bottom",
            fontsize=8.5,
            color="#333333",
        )

ax.set_ylabel("Score", fontsize=11)
ax.set_title(
    "Precision, recall, and F1 across the five-configuration ablation",
    fontsize=12.5,
    fontweight="bold",
    pad=16,
)
ax.set_xticks(x)
ax.set_xticklabels(configs, fontsize=9.5)
ax.set_ylim(0, 1.15)
ax.spines["top"].set_visible(False)
ax.spines["right"].set_visible(False)
ax.yaxis.grid(True, color="#E5E5E5", linewidth=0.7, zorder=0)
ax.set_axisbelow(True)
ax.legend(loc="upper left", frameon=False, fontsize=9.5, ncol=3, bbox_to_anchor=(0.0, 1.0))

fig.text(
    0.5,
    -0.02,
    "TRACE-Bench, 16 seeded vulnerabilities, single run per non-LLM config, 3 seeds per LLM config",
    ha="center",
    fontsize=8,
    color="#666666",
    style="italic",
)

plt.tight_layout()
plt.savefig("fig1_ablation_results.png", bbox_inches="tight", facecolor="white")
plt.close()

# ---------------------------------------------------------------------------
# Figure 2: Per-class breakdown at C5 (TP vs FN, stacked)
# ---------------------------------------------------------------------------

classes = ["BOLA", "Broken\nauthentication", "Excessive data\nexposure", "Rate\nlimiting"]
tp = [2, 0, 1, 2]
fn = [2, 4, 3, 2]

fig2, ax2 = plt.subplots(figsize=(7.5, 4.6), dpi=200)

bar_tp = ax2.bar(
    classes, tp, label="Confirmed (TP)", color="#0E8F5C", edgecolor="#075E3C", linewidth=0.6
)
bar_fn = ax2.bar(
    classes,
    fn,
    bottom=tp,
    label="Not yet covered (FN)",
    color="#E8E8E8",
    edgecolor="#B8B8B8",
    linewidth=0.6,
)

for i, (t, f) in enumerate(zip(tp, fn, strict=True)):
    if t > 0:
        ax2.annotate(
            str(t),
            xy=(i, t / 2),
            ha="center",
            va="center",
            fontsize=10,
            color="white",
            fontweight="bold",
        )
    if f > 0:
        ax2.annotate(
            str(f), xy=(i, t + f / 2), ha="center", va="center", fontsize=10, color="#666666"
        )

ax2.set_ylabel("Ground-truth vulnerabilities (of 4 per class)", fontsize=10.5)
ax2.set_title("C5 outcomes by vulnerability class", fontsize=12.5, fontweight="bold", pad=16)
ax2.set_ylim(0, 4.6)
ax2.set_yticks([0, 1, 2, 3, 4])
ax2.spines["top"].set_visible(False)
ax2.spines["right"].set_visible(False)
ax2.yaxis.grid(True, color="#E5E5E5", linewidth=0.7, zorder=0)
ax2.set_axisbelow(True)
ax2.legend(loc="upper right", frameon=False, fontsize=9.5)

fig2.text(
    0.5,
    -0.02,
    "FN includes both missed detections and endpoints with no oracle built yet",
    ha="center",
    fontsize=8,
    color="#666666",
    style="italic",
)

plt.tight_layout()
plt.savefig("fig2_per_class_c5.png", bbox_inches="tight", facecolor="white")
plt.close()

print("done")

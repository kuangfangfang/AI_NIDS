# NIDS Thesis Project — Discussion Summary

## 1. Research Foundation

We started from a 2023 IEEE conference paper (*AI-Powered Network Intrusion Detection: A New Frontier in Cybersecurity*) that compares five classical ML algorithms — Random Forest (99.88%), Gradient Boosting (99.76%), Extremely Randomized Trees (99.86%), Decision Tree (99.80%), and AdaBoost (90.00%) — on the KDD dataset.

**Key weaknesses of this paper (which define our improvement directions):**
- Uses the outdated KDD dataset (originally from 1999), which does not reflect modern network threats
- No handling of severe class imbalance — rare attack types like U2R have recall as low as 42–58%
- No model explainability — feature importance plots are shown but not meaningfully analyzed
- Limited to classical ML only, no deep learning or hybrid architectures
- No natural language reporting for security analysts

---

## 2. Proposed Research Direction

We propose a **multi-layer NIDS framework** with three stacked innovation points, building on top of the baseline paper.

### Layer 1 — Data
- **Dataset**: Replace KDD with **CICIDS2017** (modern, widely used, publicly available from the University of New Brunswick)
- **Class imbalance handling**: Apply **SMOTE or ADASYN + Tomek Links** to address the extreme imbalance in rare attack categories (e.g., Heartbleed, SQL injection)

### Layer 2 — Detection (Innovation Point 1)
- Reproduce classical ML baselines (RF, XGBoost, Decision Tree) for fair comparison with the original paper
- Add deep learning models (CNN, LSTM)
- Build a **hybrid architecture** (e.g., XGBoost + LSTM) as the main proposed model — this is the primary performance contribution

### Layer 3 — Explainability (Innovation Point 2)
- Apply **SHAP (SHapley Additive exPlanations)** to explain model decisions at the feature level
- This answers: *why* did the model flag this traffic as an attack?
- SHAP output is structured (feature attribution scores), which serves as the bridge to the LLM layer

### Layer 4 — LLM Report Generation (Innovation Point 3)
- Feed SHAP attribution values + detection results + traffic context into an LLM
- The LLM generates a **human-readable threat report**: attack classification, key indicators, recommended actions
- This closes the gap between automated detection and actionable intelligence for security analysts

---

## 3. Why These Three Innovation Points Work Together

Without SHAP, the LLM only receives a label ("DoS detected") and cannot generate meaningful reports. With SHAP, it receives structured reasoning ("src_bytes contributed 0.43 to the decision, dst_port contributed 0.31..."), enabling the LLM to produce reports like:

> *"Anomalous outbound traffic detected from 192.168.x.x targeting port 443. The primary indicator is abnormally high src_bytes (contribution: 0.43). Model confidence: 97%. Classification: DoS attack. Recommended action: isolate source host and review firewall rules."*

This makes the three layers mutually dependent — removing any one weakens the others.

---

## 4. Technical Stack

| Component | Tool / Method |
|---|---|
| Dataset | CICIDS2017 (free download, also on Kaggle) |
| Class balancing | imbalanced-learn (SMOTE, ADASYN, Tomek Links) |
| ML models | scikit-learn (RF, XGBoost, Decision Tree) |
| DL models | TensorFlow / PyTorch (LSTM, CNN) |
| Explainability | SHAP library |
| LLM API | Groq (free tier, LLaMA-3.3-70B, no credit card needed) |
| Compute | Google Colab free tier + Kaggle Notebooks (both free) |

**Estimated cost: ~$0** — Groq offers 14,400 free API requests/day, Colab and Kaggle provide free GPU access sufficient for our model sizes.

---

## 5. Real Technical Challenges

These are the parts that require actual research effort (not just code):

1. **Hybrid architecture design** — how exactly to combine XGBoost and LSTM (feature fusion, stacking, or sequential pipeline) is a design decision that needs experimental validation

2. **SHAP-to-LLM interface** — converting raw SHAP numerical values into meaningful natural language context for the LLM prompt requires careful prompt engineering and iterative testing

3. **Evaluating LLM report quality** — this is the hardest part. How do we prove the generated reports are useful? Options include human evaluation rubrics, comparison against expert-written reports, or automated metrics (BLEU/ROUGE). Each has trade-offs and we need to pick a defensible approach

4. **Class imbalance results are unpredictable** — SMOTE improves some attack classes and may hurt others. The actual results need to be discovered experimentally, and explaining those results is part of the research contribution

---

## 6. What We Can Realistically Deliver

| Minimum viable thesis | Full thesis with all three innovation points |
|---|---|
| CICIDS2017 + SMOTE + ML/DL comparison + SHAP | Above + hybrid architecture + LLM report generation |
| Solid, defensible, ~10–14 weeks | More ambitious, stronger publication potential |

The minimum viable version is already a significant improvement over the baseline paper. The full version positions the thesis closer to current state-of-the-art research (2024–2025).

---

## 7. Suggested Next Steps

1. Both team members download CICIDS2017 and run initial EDA (exploratory data analysis) to understand the class distribution
2. Reproduce the baseline ML results from the original paper on CICIDS2017 (establishes the starting point)
3. Decide together: do we go for the minimum viable version or the full three-layer framework?
4. Set up a shared Colab/Kaggle notebook environment

---

*Summary prepared based on a full literature review and discussion session. All referenced datasets and tools are freely and publicly available.*

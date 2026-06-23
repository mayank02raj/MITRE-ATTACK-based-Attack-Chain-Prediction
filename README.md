# MITRE ATT&CK-based Attack Chain Prediction using Hybrid LSTM-Markov Models

[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![PyTorch](https://img.shields.io/badge/pytorch-2.2-ee4c2c.svg)](https://pytorch.org/)
[![CUDA](https://img.shields.io/badge/cuda-12.2-76B900.svg)](https://developer.nvidia.com/cuda-toolkit)
[![License](https://img.shields.io/badge/license-see%20below-lightgrey.svg)](#license-and-release-terms)
[![Paper](https://img.shields.io/badge/paper-under%20review%20%40%20SECRYPT%202026-b31b1b.svg)](#paper)
[![ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v16.0-FC4C02.svg)](https://attack.mitre.org/)

A hybrid LSTM–Markov framework for **forecasting multi-stage adversary progressions** against the MITRE ATT&CK framework. Learns technique-to-technique transition patterns from 4,849 ATT&CK-mapped campaign chains (long-range dependencies via a 2-layer LSTM) and 8,437 operational intrusion flows (short-range priors via a first-order Markov model), then uses constrained beam search to synthesize plausible forward attack paths from observed prefixes. A formally defined risk scoring model integrates per-technique likelihood (EPSS + CAPEC + LSTM confidence + CISA KEV), detectability (D3FEND coverage), and OCTAVE-based organizational impact into a continuous 0–10 severity scale.

**86% next-step prediction accuracy. Pearson r = 0.76 and Spearman ρ = 0.81 correlation against NCISS reference severity. 42.3% real-world transition coverage across 26,051 risk-ranked future chains.**

Supports the paper:

> **Raj, M.**, Kul, G., Bastian, N. D., Fiondella, L. *MITRE ATT&CK-based Attack Chain Prediction using Hybrid LSTM-Markov Models for Cyber Risk Assessment.* ACCEPTED at SECRYPT 2026.

## The shift from reactive to predictive

Intrusion detection systems surface malicious activity *after* it executes. That is necessary, but not sufficient. Modern adversaries chain tactics and techniques into multi-stage sequences that unfold over hours or days — phishing leads to credential dumping leads to lateral movement leads to exfiltration. By the time a SOC sees the exfiltration alert, the attacker has already won.

This work asks a different question: given the three or four steps a defender has observed, what is the attacker **likely to do next**, and how urgently should the defender act? Existing answers are incomplete. Attack graphs enumerate possible paths without prioritizing likely ones. Hidden Markov Models capture local transitions but not long-range campaign intent. RNN-based stage classifiers predict the next technique but not scored multi-step continuations with explicit defensive urgency.

**This repository combines global campaign-level sequence learning (LSTM) with empirical real-world transition priors (Markov) and a formally defined risk engine, producing not just predictions but risk-ranked forecasts that a SOC can act on.**

## Headline results

|Metric                          |Value                                                          |
|--------------------------------|---------------------------------------------------------------|
|Next-step prediction accuracy   |**86%** (stable across 100%, 50/50, and 80/20 training regimes)|
|NCISS severity correlation      |Pearson r = **0.76** · Spearman ρ = **0.81** (80/20 scenario)  |
|Mean absolute error vs. NCISS   |**1.21** (80/20) · 1.28 (50/50) on 0–10 severity scale         |
|Predictions within ±1.0 of NCISS|**62.1%** · within ±1.5: 72.0% · within ±2.0: 84.6%            |
|Markov transition coverage      |**42.3%** mean (median 41.7%) on tactic-level alignment        |
|Sequences above 50% coverage    |38.1%                                                          |
|Forecast generation throughput  |**206 sequences/sec** (beam width 50, Top-10 branching)        |
|Beam expansion memory           |Under 7.2 GB for 26,051 multi-step forecasts                   |
|Inference latency per prefix    |< 0.2 sec (SOC-workflow compatible)                            |

## Architecture

The framework is a three-phase inference pipeline over five architectural components:

```
  Phase 1: Markov Beam Expansion       Phase 2: LSTM Re-scoring
  ───────────────────────────────      ──────────────────────────
  Observed prefix S = {t1,t2,t3}       Re-rank candidates by
           │                            PLSTM(seq) for long-range
           ▼                            campaign-level coherence
  Markov Top-K branching                        │
  (empirical transition freq)                   ▼
           │                            Phase 3: Risk Scoring
           ▼                            ──────────────────────────
  Retain Top-B by PMarkov               Per-technique L_i (EPSS,
  (beam width = 50)                     CAPEC, LSTM, CISA KEV)
           │                                    │
           ▼                                    ▼
  Candidate multi-step paths            D_i (D3FEND coverage)
                                                │
                                                ▼
                                       Chain geometric-mean
                                       likelihood L_chain
                                                │
                                                ▼
                                       R = min(10, 10·L_chain·I/10)
                                       where I is OCTAVE impact
                                                │
                                                ▼
                                       Risk-ranked forecast list
```

The hybrid design is necessary because **LSTM alone overgeneralizes rare transitions** (smooth prediction, but generates plausible-looking paths that real attackers never execute) and **Markov alone lacks memory** (each transition conditioned only on the previous technique, losing campaign narrative). Combined, the two components constrain each other: Markov priors keep forecasts within empirically observed transitions, LSTM re-ranks them by global campaign plausibility.

## Five architectural components

```
  1. ATT&CK Knowledge Ingestion
     ATT&CK Enterprise v16.0 → 203 parent + 453 sub-techniques
     → Filter to techniques in ≥1 campaign → 239 unique TIDs
     → Normalize via STIX ID ↔ ATT&CK TID ↔ human-readable name
     → Expand parent techniques into sub-techniques (Eq. 1)

  2. Campaign Chain Construction
     73 MITRE campaigns → 33 with chains of length ≥ 3
     → Tactic-bucketed permutation (≤6: enumerate; >6: sample 25)
     → Cartesian product across non-empty tactic groups
     → 4,849 training chains (median length 9, range 3–27)

  3. LSTM Sequence Learning
     2-layer LSTM, 256 hidden units, 128-dim embeddings
     Dropout p=0.2, AdamW lr=0.003, batch size 64, 50 epochs
     Prefix→target training via sliding sequence windows
     Chain probability P_LSTM(C) = ∏ P(t_i | t_1..i−1)

  4. Markov Transition Priors & Beam Expansion
     First-order Markov trained on 8,437 real-world sequences
     Sources: Unit42 Playbook Viewer (85 STIX bundles) +
              MITRE Attack Flow v3.0 (39 flow documents)
     72 start states, 1,621 unique transitions
     Constrained beam search: width 50, Top-10 branching,
     max horizon 20, 800 seed prefixes → 26,051 forecasts

  5. Risk Scoring
     L_i = priority lookup across EPSS → CAPEC → LSTM → default
     CISA KEV bonus: L_i ← min(1.0, L_i + 0.1) if in catalog
     D_i = 1 − D3FEND_coverage(t_i)
     L_chain = geometric mean of max(L_i, 1e-12)
     R = min(10, 10 · L_chain · I_OCTAVE / 10)
```

## Three research contributions

1. **A reproducible ATT&CK-anchored dataset for attack-chain learning** — 4,849 campaign chains from 33 MITRE campaigns, plus 8,437 real-world intrusion sequences from Unit42 and MITRE Attack Flow, released for downstream research.
1. **A hybrid LSTM–Markov forecaster** capable of long-horizon progression simulation via constrained beam search, achieving 42.3% tactic-level coverage against operationally observed transitions with 86% next-step accuracy.
1. **A continuous, interpretable 0–10 risk scoring model** that integrates per-technique likelihood (EPSS, CAPEC, LSTM, CISA KEV), detectability (D3FEND coverage), and OCTAVE-based organizational impact — producing SOC-actionable severity estimates that correlate with NCISS reference scores at Pearson r = 0.76.

## What’s in this repository

|Component                  |Purpose                                                                                                                                                |
|---------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------|
|ATT&CK ingestion           |Parses MITRE ATT&CK Enterprise v16.0, normalizes STIX ↔ TID ↔ name, expands parent techniques into sub-techniques                                      |
|Campaign chain builder     |Constructs 4,849 tactic-ordered chains from 33 MITRE campaigns with permutation sampling (≤6 exhaustive, >6 cap at 25)                                 |
|LSTM trainer               |2-layer LSTM with 256 hidden units, 128-dim embeddings, dropout 0.2, AdamW optimizer, three training scenarios (100%, 50/50, 80/20)                    |
|Unit42 + Attack Flow parser|Extracts technique sequences from 85 Unit42 STIX playbooks and 39 MITRE Attack Flow v3.0 documents via DFS traversal                                   |
|Markov transition model    |First-order model over 72 start states and 1,621 unique transitions from 8,437 sequences                                                               |
|Beam search engine         |Constrained generation with width 50, Top-10 branching, max horizon 20, stream-safe expansion                                                          |
|Risk scoring engine        |Per-technique likelihood lookup (EPSS → CAPEC → LSTM → default), CISA KEV bonus, D3FEND detectability, OCTAVE impact, chain-level geometric aggregation|
|NCISS evaluation harness   |Ground-truth severity benchmarking against CISA NCISS rubric for 33 campaigns, reporting MAE, median AE, Pearson r, Spearman ρ                         |
|ACI-IoT-2023 mapper        |Maps ACI-IoT-2023 intrusion alerts to ATT&CK techniques, enabling dataset-anchored prediction beyond campaign-derived inputs                           |
|Case-study reproduction    |Generates the lateral-movement forecast walkthrough in paper §6 from the observed prefix (Phishing → PowerShell → Credential Dumping)                  |

## Quick start

```bash
git clone https://github.com/mayank02raj/ATTACK-Chain-Prediction.git
cd ATTACK-Chain-Prediction

# Environment (Python 3.11+, CUDA 12.2 recommended)
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Data — MITRE ATT&CK Enterprise v16.0 + Unit42 playbooks + Attack Flow
# All included via public STIX bundles; see data/README.md

# Train the LSTM (80/20 split, ~3.1 hrs on RTX 4090)
python train_lstm.py --scenario 80-20 --epochs 50

# Train the Markov model (< 1 sec)
python train_markov.py --sources unit42 attack_flow

# Generate 26,051 forecasts from 800 seed prefixes
python generate_forecasts.py --beam-width 50 --top-k 10 --max-horizon 20

# Score and rank by risk
python score_risks.py --impact-octave 10

# Evaluate against NCISS
python evaluate_nciss.py --scenario 80-20
```

Full pipeline (training + generation + evaluation) runs in roughly 4 hours on the reference hardware. Forecast generation alone is fast enough for SOC workflows: < 0.2 seconds per prefix at inference time.

## Reproducibility

|Setting                            |Value                                                                        |
|-----------------------------------|-----------------------------------------------------------------------------|
|Python                             |3.11                                                                         |
|PyTorch                            |2.2.1                                                                        |
|CUDA / cuDNN                       |12.2 / 8.9                                                                   |
|NumPy / Pandas / SciPy / Matplotlib|pinned in requirements.txt                                                   |
|OS                                 |Ubuntu 22.04 LTS                                                             |
|Hardware (paper results)           |NVIDIA RTX 4090 (16 GB VRAM), AMD Ryzen 9, 64 GB RAM                         |
|LSTM architecture                  |2 layers × 256 hidden units, 128-dim embeddings, dropout 0.2                 |
|LSTM optimizer                     |AdamW, lr = 0.003, batch size 64                                             |
|Training epochs                    |50                                                                           |
|Training scenarios                 |100%, 50/50, 80/20 (identical architecture; isolates data-volume sensitivity)|
|Markov order                       |First-order (8,437 training sequences, 72 start states, 1,621 transitions)   |
|Beam search                        |Width 50, Top-10 branching, max horizon 20                                   |
|Seed prefixes                      |800 (first 800 LSTM-scored chains, 3-technique prefix each)                  |
|Generated forecasts                |26,051                                                                       |
|ATT&CK knowledge base              |Enterprise v16.0 (203 parent + 453 sub-techniques, 14 tactics)               |
|Risk score range                   |0–10 continuous                                                              |
|OCTAVE impact (paper)              |I = 10 worst-case (operational deployments would vary per asset class)       |

## Three research questions, three clean findings

**RQ1 — Does the hybrid framework generalize across training set sizes?**
Yes. All three training configurations converge rapidly (within 15–20 epochs) and stabilize near 86% accuracy with minimal overfitting (< 0.5% train-validation gap). The 80/20 configuration yields the lowest MAE (1.21), reducing median prediction error by 10% relative to 50/50, with Pearson r = 0.76 and Spearman ρ = 0.81 correlation against NCISS. Performance degrades by only 6.4% in MAE when halving training data, suggesting reasonable robustness to limited telemetry availability.

**RQ2 — Does the Markov engine produce realistic future attack sequences?**
Yes. The framework achieves 42.3% mean tactic-level coverage (median 41.7%) across 4,849 LSTM chains, with 38.1% of sequences above 50% coverage. Seeds with strong empirical transition support expand deeply; low-support prefixes produce shallow trees — meaningful resistance against unrealistic over-generation. Beam expansion achieves 206 sequences/sec with memory usage under 7.2 GB.

**RQ3 — Are generated risk scores aligned with known high-impact campaigns?**
Yes. 51% of predictions score above 8.0, 73% above 7.0, only 8% above 9.0 (indicating the scoring engine reserves high-risk classifications for genuinely rare, multi-stage, low-detectability progressions). NCISS-aligned MAE in the 7.1–10.0 severity band is 1.04, meaning the model is most accurate precisely where prediction value is highest — in the critical-escalation zone SOC teams care about most.

## Risk-ranked forecasts: representative examples

From Table 3 in the paper — real output of the pipeline across the full risk spectrum:

|Attack Chain                                                                                                                                                          |Steps|Likelihood|Risk    |
|----------------------------------------------------------------------------------------------------------------------------------------------------------------------|----:|---------:|-------:|
|Gather Victim Info → Develop Malware → Establish Accounts → Compromise Infrastructure → Spearphishing → PowerShell → Process Injection → LSASS Dumping → Exfil over C2|10   |0.917     |**9.17**|
|Active Scanning → Obtain Tools → PowerShell → Scheduled Task → Systemd Service → Masquerading → Valid Accounts → SSH → Data Encrypted for Impact                      |10   |0.874     |**8.74**|
|Spearphishing Link → JavaScript → User Execution → Registry Run Keys → Process Injection → Credential Stores → Lateral Tool Transfer → Archive                        |8    |0.791     |7.91    |
|Exploit Public-Facing App → Unix Shell → Create Local Account → Indicator Removal → Network Discovery → Web App Layer Protocol                                        |7    |0.682     |6.82    |
|Supply Chain Compromise → Client Exploitation → Registry Autostart → Obfuscation → Account Discovery → Local Data                                                     |6    |0.567     |5.67    |
|Valid Domain Accounts → SMB Admin Shares → System Info Discovery → File Discovery → Screen Capture                                                                    |5    |0.453     |4.53    |
|Network Service Discovery → Vuln Scanning → Exploit Public App → User Discovery → Network Sniffing                                                                    |5    |0.341     |3.41    |

Seven examples spanning the full 0.89–9.17 risk range, all produced by the same pipeline from different seed prefixes. High-risk chains cluster on the familiar APT campaign pattern (multi-stage staging + credential theft + low-detectability exfiltration); low-risk chains reflect isolated reconnaissance or dead-end activity.

## Case study: forecasting a real intrusion prefix

Paper §6 walks through the following scenario. A defender captures three observed steps:

```
S = { T1566.001  Phishing: Spearphishing Attachment,
      T1059      Command/Scripting Interpreter: PowerShell,
      T1003      OS Credential Dumping }
```

The pipeline generates 50 candidate futures per beam step and returns the top five risk-ranked continuations:

|Predicted Continuation                        |P_LSTM · P_Markov|Risk   |
|----------------------------------------------|----------------:|------:|
|Lateral Movement → Data Staging → Exfiltration|0.427            |**9.4**|
|Account Discovery → Exfil via Cloud           |0.391            |8.8    |
|Kerberoasting → Domain Shadowing              |0.355            |8.3    |
|Remote Service Execution Loop (Persistence)   |0.214            |6.7    |
|Data Staging Only (No Exfil)                  |0.151            |5.9    |

The highest-scoring forecast matches the observed post-dump behavior of APT29, APT32, and FIN7 campaigns. **Operational value:** instead of responding after exfiltration, a SOC armed with this forecast can pre-emptively enforce credential reset, enable LSASS access auditing, isolate outbound HTTP/S from staging directories, and rotate MFA for high-value domain accounts — interrupting the campaign at the lateral-movement pivot where defensive cost is lowest and leverage is highest.

## SOC integration

Model outputs are designed for SOAR platforms:

- **Continuous 0–10 risk score** per predicted continuation, suitable for threshold-based alerting
- **Scores ≥ 8.0** trigger critical escalation and playbook automation
- **Scores 6.0–8.0** trigger warning alerts
- **Scores < 6.0** logged for situational awareness
- Top-K ranked forecasts map directly to defensive playbooks (credential rotation, network segmentation, EDR hunting queries)
- **Inference latency < 0.2 sec per prefix** — compatible with minute-to-hour SOC triage cadence
- LSTM training is offline (~3.1 hrs) and does not need to run at inference time

## Why this work matters

The cybersecurity industry has spent two decades building detection systems. It has spent far less time building prediction systems. The difference matters because detection is a **cost-reduction** tool — you catch the attacker a little earlier — while prediction is a **cost-prevention** tool — you interrupt the campaign before it completes.

Moving SOC operations from “what has the attacker done?” to “what will they do next?” is the same shift that weather forecasting represented for disaster response. The methods here — hybrid sequence modeling, constrained beam search, risk-weighted probability scoring — are the beginning of that shift for cyber defense. The 86% next-step accuracy and 0.76 NCISS correlation are not enough to replace defenders, but they are enough to reduce triage burden and guide targeted mitigation before exploitation completes.

## Skills demonstrated

Sequence modeling (LSTM, Markov chains), constrained beam search, graph-structured risk scoring, MITRE ATT&CK framework fluency, STIX 2.0/2.1 parsing, threat-intelligence integration (EPSS, CAPEC, CISA KEV, D3FEND), cyber risk quantification (OCTAVE, NCISS), experimental design under multiple training regimes, Unit42 and MITRE Attack Flow data engineering, scientific Python tooling, PyTorch training pipelines on GPU.

## Skills mapped to job postings

- **“MITRE ATT&CK alignment”** — pipeline built directly on ATT&CK v16.0, parses 239 techniques across 14 tactics
- **“Threat-informed defense”** — forecasts aligned with real-world Unit42 and MITRE Attack Flow intrusion sequences
- **“Cyber risk scoring”** — formal 0–10 model integrating EPSS, CAPEC, LSTM confidence, CISA KEV, D3FEND, OCTAVE impact
- **“SOC / SOAR integration”** — < 0.2 sec inference latency, threshold-based alerting, playbook mapping
- **“Machine learning for cybersecurity”** — 2-layer LSTM on GPU, Markov priors, constrained beam search
- **“STIX 2.x parsing”** — Unit42 Playbook Viewer STIX 2.0 + MITRE Attack Flow STIX 2.1
- **“Threat intelligence engineering”** — integration with EPSS, CAPEC, CISA KEV, D3FEND, NCISS
- **“Collaboration with government / defense research”** — DoD Cooperative Agreement, collaboration with U.S. Military Academy at West Point

## Related work in my portfolio

This repository is the forward-looking companion to the rest of my portfolio:

- [`Robustness-of-NIDS`](https://github.com/mayank02raj/Robustness-of-NIDS) — adversarial robustness of per-packet NIDS (three-architecture comparison under FGSM/PGD/CLEVER, the **False Champion Problem**). IEEE Access submission.
- [`Synthetic-Network-Packet-Generation`](https://github.com/mayank02raj/Synthetic-Network-Packet-Generation) — constraint-enforcing synthetic packet generation for data-scarce IoT attacks (statistical + GA methods). ICCCN 2026 submission.
- [`SOC-home-lab`](https://github.com/mayank02raj/SOC-home-lab) — detection infrastructure with 11-service Dockerized SOC, Sigma rules, 8-stage ATT&CK adversary emulation
- [`ATTACK-Coverage-Dashboard`](https://github.com/mayank02raj/ATTACK-Coverage-Dashboard) — MITRE ATT&CK detection-coverage analytics with weighted scoring across 130+ threat actors
- [`Phishing-URL-Detector`](https://github.com/mayank02raj/Phishing-URL-Detector) — production-shaped ML service with SHAP explainability

Across the portfolio, the story spans the full defensive stack: measure where detectors fail under adversarial pressure (Robustness-of-NIDS), generate the training data needed to fix them (Synthetic-Network-Packet-Generation), know where your ATT&CK coverage is honest (ATTACK-Coverage-Dashboard), run everything in a realistic SOC (SOC-home-lab), ship production ML (Phishing-URL-Detector), and — with this repository — forecast what the adversary will do next.

## Paper

**MITRE ATT&CK-based Attack Chain Prediction using Hybrid LSTM-Markov Models for Cyber Risk Assessment.**
Raj, M., Kul, G., Bastian, N. D., Fiondella, L.
*Under review at SECRYPT 2026.*

Preprint available on request — please reach out via the contact details below. If you use this work, please cite:

```bibtex
@inproceedings{raj2026attack,
  title     = {MITRE ATT\&CK-based Attack Chain Prediction using Hybrid
               LSTM-Markov Models for Cyber Risk Assessment},
  author    = {Raj, Mayank and Kul, Gokhan and Bastian, Nathaniel D. and
               Fiondella, Lance},
  booktitle = {International Conference on Security and Cryptography (SECRYPT)
               (under review)},
  year      = {2026},
  note      = {Preprint available on request}
}
```

## Funding and disclaimer

This work was supported by the U.S. Military Academy (USMA) under Cooperative Agreement No. W911NF-22-2-0160.

The views and conclusions expressed in this paper are those of the authors and do not reflect the official policy or position of the U.S. Military Academy or U.S. Army.

## License and release terms

License status is **pending institutional review** prior to open-source release.

This repository contains research software produced under a U.S. Department of Defense Cooperative Agreement (W911NF-22-2-0160). Data rights, release terms, and applicable open-source licensing are being confirmed with:

- The Principal Investigator (Dr. Gokhan Kul, UMass Dartmouth)
- UMass Dartmouth’s Office of Research Administration
- Co-investigator institutions (U.S. Military Academy at West Point)

Until a formal license is posted, please contact the corresponding author before using, redistributing, or building on this code. For academic evaluation and review of the paper’s results, the code is provided as-is. A formal license file (`LICENSE`) will be added to this repository once release terms are finalized.

## Contact

**Mayank Raj** — M.S. Data Science (Thesis Track), UMass Dartmouth · Graduating May 2026

- Portfolio: [mayank02raj.github.io](https://mayank02raj.github.io)
- LinkedIn: [linkedin.com/in/mayank02raj](https://linkedin.com/in/mayank02raj)
- GitHub: [github.com/mayank02raj](https://github.com/mayank02raj)
- Email: mraj1@umassd.edu

Open to full-time cybersecurity and ML-security roles in the US. F-1 STEM OPT eligible — no sponsorship required through August 2029.

## Limitations and honest caveats

The paper is transparent about the following, and so is this README:

1. **First-order Markov assumption.** Transitions depend only on the immediately preceding technique. Second-order or higher-order dependencies (e.g., “reconnaissance → dwell → lateral movement” patterns) are captured only via the LSTM component, not the Markov prior.
1. **Reporting bias in training data.** Publicly documented intrusion traces over-represent well-studied APT campaigns and under-represent stealthy, commodity, or supply-chain operations. Rare transitions are learned weakly or omitted entirely.
1. **Probabilistic uncertainty compounds with sequence depth.** Predictions beyond 8–12 steps carry increasing variance, particularly for chains containing transitions with weak empirical support.
1. **Worst-case OCTAVE impact assumption.** All experiments use I = 10, producing R = 10 · L_chain (linear relationship by design, visible in Figure 4 of the paper). Operational deployments would vary I per asset class (e.g., I = 3 for user workstations, I = 9 for domain controllers), breaking the linearity and producing differentiated rankings even for chains with identical likelihood profiles.
1. **No classical temporal generalization study.** The 100% / 50/50 / 80/20 scenarios test sensitivity to training-data volume, not temporal or campaign-holdout generalization. Leave-one-campaign-out cross-validation is identified as future work.
1. **Tactic-level Markov coverage rather than technique-level.** The 42.3% coverage metric reflects matching classes of transitions across corpora, not exact technique-ID matching. Technique-level coverage is lower because campaign-derived and operational corpora use partially overlapping vocabularies. Semantically meaningful but worth flagging.
1. **Chain-level consistency vs. campaign-level ground truth.** All 4,849 chains from 33 campaigns share N = 33 independent NCISS severity labels. Chain-level error metrics reflect within-campaign prediction consistency; correlation metrics reflect cross-campaign ranking agreement. Finer-grained per-chain ground-truth annotation is future work.
1. **Model is not omniscient.** Forecast quality decreases when attackers deviate from historically observed strategies, particularly when transitions have low prior frequency or are absent from training data. The framework flags this via low likelihood scores rather than masking it.

## Extension ideas

- Incorporate temporal dwell-time distributions, noise injection, and deception behavior to simulate adaptive APT tradecraft under detection pressure
- Integrate streaming event pipelines for sliding-window prediction on live telemetry — enabling real-time risk elevation and kill-chain interruption
- Replace uniform defender posture with organization-specific detection coverage, asset criticality, and response latency for contextualized prioritization
- Replace LSTM with GNNs or Transformers over ATT&CK knowledge graphs to learn cross-tactic relationships beyond linear ordering
- Systematic ablation over beam search hyperparameters (beam width, branching, seed length) with statistical-significance testing vs. baselines (Markov-only, frequency-based, random)
- Temporal holdout and leave-one-campaign-out cross-validation to strengthen generalization evidence beyond static train–test splits
- Integration with [`ATTACK-Coverage-Dashboard`](https://github.com/mayank02raj/ATTACK-Coverage-Dashboard) so predicted attack continuations are automatically scored against organizational detection coverage — flagging “high-risk + low-coverage” chains as priority defensive investments

## Co-authors

- **Dr. Nathaniel D. Bastian** — Deputy Director of Robotics Research Center, U.S. Military Academy at West Point
- **Dr. Lance Fiondella** — Director of Cybersecurity Center, UMass Dartmouth (NSA/DHS-designated CAE-R)
- **Dr. Gokhan Kul** (advisor) — Associate Director of Cybersecurity Center, UMass Dartmouth

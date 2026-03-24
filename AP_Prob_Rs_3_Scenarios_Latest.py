# AP_Prob_RS_Complete_3_Scenarios.py
# Complete implementation preserving ALL original functionality
# PLUS: 3 training scenarios (100%, 50/50, 80/20) with error analysis vs NCISS scores
# 
# Original pipeline flow (ALL PRESERVED):
# 1) MITRE ATT&CK techniques/sub-techniques + Campaigns (Excel)
# 2) Tactic-ordered chains from campaigns (pre-LSTM)
# 3) Train LSTM on chains + post-LSTM probability + risk
# 4) Ingest Unit42 Playbooks (local) + Attack Flow JSON (local) -> sequences
# 5) Train first-order Markov on JSON-only sequences
# 6) Validate + (6b) stream-safe Markov expansions of LSTM chains
# 7) Score Markov sequences (risk then probability)
# 8) (Optional) Dataset mapping → filter + rank
# 8b) Dataset-anchored predictions: start from dataset attack types, predict next steps
# + Save catalogs, plots, README, and print important counts.
#
# NEW ADDITIONS:
# 9) Three-scenario LSTM training (100% TRUE training - no validation, 50/50, 80/20)
# 10) Error rate calculation for 50/50 and 80/20 scenarios only
# 11) Cross-scenario comparison and visualization

import os, re, math, random, warnings, time, logging, json, datetime, glob, csv, signal, sys
from collections import defaultdict, Counter
from itertools import islice, permutations, product
from typing import List, Dict, Tuple

import pandas as pd
import numpy as np

import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from tqdm.auto import tqdm
import matplotlib.pyplot as plt

warnings.filterwarnings("ignore", category=UserWarning, message="This figure includes Axes that are not compatible with tight_layout*")

# =========================================================
# 0) CONFIG — EDIT THESE PATHS (or set env vars)
# =========================================================
ATTACK_FILE = os.environ.get("ATTACK_FILE",
    '/Users/mayankraj/Desktop/RESEARCH/6. Attack Prediction and Risk Score/Enterprise attack csvs/enterprise-attack-v16.0.xls')
UNIT42_REPO_DIR = os.environ.get("UNIT42_REPO_DIR",
    '/Users/mayankraj/Desktop/RESEARCH/6. Attack Prediction and Risk Score/playbook_viewer-master')
ATTACK_FLOW_STIX_DIR = os.environ.get("ATTACK_FLOW_STIX_DIR",
    "/Users/mayankraj/Desktop/RESEARCH/6. Attack Prediction and Risk Score/Attack flows")
OUT_ROOT = os.environ.get("OUT_ROOT",
    "/Users/mayankraj/Desktop/RESEARCH/6. Attack Prediction and Risk Score/")

EPSS_CSV       = os.environ.get("EPSS_CSV", "")
KEV_CSV        = os.environ.get("KEV_CSV", "")
DETECTION_CSV  = os.environ.get("DETECTION_CSV", "")

SEVERITY_CSV = os.environ.get("SEVERITY_CSV", "/Users/mayankraj/Desktop/RESEARCH/6. Attack Prediction and Risk Score/MITRE Campaign severity score/MITRE_Campaign_Severity_Scores.csv")

OCTAVE_IMPACT_0_10_DEFAULT = float(os.environ.get("OCTAVE_IMPACT", "10.0"))

DATASET_PATH  = os.environ.get("DATASET_PATH", "")
DATASET_LABEL = os.environ.get("DATASET_LABEL", "Label")

LOG_LEVEL = logging.INFO
TRAIN_PROGRESS_EVERY = 200
SEED = 42

MIN_CHAIN_LEN = 3
MAX_PERMS_PER_TACTIC = 25
MAX_FULL_CHAINS_PER_CAMPAIGN = 200
TACTIC_ORDER_DEFAULT = [
    "reconnaissance","resource development","initial access","execution","persistence",
    "privilege escalation","defense evasion","credential access","discovery",
    "lateral movement","collection","command and control","exfiltration","impact"
]

EMBED_DIM = 128
HIDDEN_DIM = 256
NUM_LAYERS = 2
DROPOUT = 0.2
BATCH_SIZE = 64
EPOCHS = 50
LR = 3e-3

MARKOV_TOPK_NEXT = 10
MARKOV_BEAM = 50
MARKOV_MAX_LEN = 20
MARKOV_MIN_PROB = 1e-12

POST_MARKOV_MAX_CHAINS = int(os.environ.get("POST_MARKOV_MAX_CHAINS", "800"))
POST_MARKOV_EXPAND_SEED_LEN = int(os.environ.get("POST_MARKOV_EXPAND_SEED_LEN", "3"))
POST_MARKOV_LOG_EVERY = int(os.environ.get("POST_MARKOV_LOG_EVERY", "50"))
SKIP_POST_MARKOV_EXPANSION = os.environ.get("SKIP_POST_MARKOV_EXPANSION", "0") == "1"

RUN_THREE_SCENARIOS = os.environ.get("RUN_THREE_SCENARIOS", "1") == "1"

random.seed(SEED); np.random.seed(SEED); torch.manual_seed(SEED)

# =========================================================
# 0.1) Logger + Output folder + graceful-cancel
# =========================================================
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s | %(levelname)-7s | %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("attack-chain-pipeline")

def section(title):
    line = "=" * 38
    log.info(f"\n{line}\n{title}\n{line}")

STAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
OUT_DIR = os.path.join(OUT_ROOT, f"ATTACK_{STAMP}")
os.makedirs(OUT_DIR, exist_ok=True)

def save_fig(path):
    plt.tight_layout()
    plt.savefig(path, dpi=150)
    plt.close()

ABORT = [False]
def _handle_signal(sig, frame):
    log.warning(f"Received signal {sig}. Finishing current item and exiting gracefully...")
    ABORT[0] = True
for _sig in (signal.SIGINT, signal.SIGTERM):
    try:
        signal.signal(_sig, _handle_signal)
    except Exception:
        pass

# =========================================================
# Helpers: Unit42 + Attack Flow + Markov
# =========================================================
def unit42_sequences_from_file(fp, tactic_order, ATTACK_ID_TO_NAME):
    try:
        with open(fp, "r", encoding="utf-8") as f:
            bundle = json.load(f)
    except Exception as e:
        log.warning(f"Unit42 parse failed: {fp} ({e})")
        return os.path.basename(fp), []
    objs = bundle.get("objects", [])
    playbook_name = next((o.get("name") for o in objs if o.get("type") == "report"), os.path.basename(fp))

    tactic_buckets = {t: [] for t in tactic_order}
    for o in objs:
        if o.get("type") != "attack-pattern":
            continue
        name = o.get("name")
        if not name:
            ext = o.get("external_references", []) or []
            tid = None
            for ref in ext:
                sid = ref.get("external_id", "")
                if isinstance(sid, str) and re.match(r"^T\d{4}(\.\d{3})?$", sid):
                    tid = sid; break
            if tid and tid in ATTACK_ID_TO_NAME:
                name = ATTACK_ID_TO_NAME[tid]
        if not name:
            continue
        tac = None
        for p in o.get("kill_chain_phases", []) or []:
            phase = str(p.get("phase_name", "")).lower()
            kcn = str(p.get("kill_chain_name", "")).lower()
            if phase in tactic_buckets and ("mitre" in kcn or kcn.startswith("mitre")):
                tac = phase; break
        if tac:
            tactic_buckets[tac].append(name)

    buckets = [tactic_buckets[t] for t in tactic_order if tactic_buckets[t]]
    if not buckets:
        return playbook_name, []

    def sample_perms(bucket: list, k: int):
        b = list(dict.fromkeys(bucket))
        if len(b) <= 1: return [tuple(b)]
        if len(b) <= 6: return list(islice(permutations(b), k))
        out = set(); trials = 0
        while len(out) < k and trials < k*20:
            sh = b[:]; random.shuffle(sh); out.add(tuple(sh)); trials += 1
        return list(out)

    perms_per_bucket = [sample_perms(b, MAX_PERMS_PER_TACTIC) for b in buckets]
    sequences = []
    for combo in islice(product(*perms_per_bucket), MAX_FULL_CHAINS_PER_CAMPAIGN):
        flat = [x for group in combo for x in group]
        if len(flat) >= MIN_CHAIN_LEN:
            sequences.append(flat)
    return playbook_name, sequences

def load_unit42_sequences(repo_dir, tactic_order, ATTACK_ID_TO_NAME):
    out = []
    json_dir = os.path.join(repo_dir, "playbook_json")
    if not os.path.isdir(json_dir):
        log.warning(f"Unit42 directory missing 'playbook_json': {json_dir}")
        return out
    files = sorted(glob.glob(os.path.join(json_dir, "*.json")))
    log.info(f"Unit42: found {len(files)} playbook JSON files.")
    for fp in tqdm(files, desc="Unit42 playbooks", leave=False):
        name, seqs = unit42_sequences_from_file(fp, tactic_order, ATTACK_ID_TO_NAME)
        for s in seqs:
            out.append(("Unit42", name, s))
    return out

def af_sequences_from_file(fp, ATTACK_ID_TO_NAME):
    try:
        with open(fp, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        log.warning(f"Attack Flow parse failed: {fp} ({e})")
        return os.path.basename(fp), []
    objs = data.get("objects", [])
    if not isinstance(objs, list):
        objs = [o for o in data.values() if isinstance(o, dict)]
    by_id = {o.get("id"): o for o in objs if isinstance(o, dict) and o.get("id")}
    flow = next((o for o in objs if o.get("type") == "attack-flow"), None)
    if not flow:
        return os.path.basename(fp), []
    flow_name = flow.get("name", os.path.basename(fp))
    starts = flow.get("start_refs", []) or []
    paths = []
    seen_cap = [0]
    AF_MAX_PATHS_PER_FILE = 5000

    def action_name(o):
        tid = str(o.get("technique_id", "")).strip()
        if tid and tid in ATTACK_ID_TO_NAME:
            return ATTACK_ID_TO_NAME[tid]
        tref = o.get("technique_ref")
        if tref and tref in by_id:
            nm = by_id[tref].get("name")
            if nm: return nm
        return o.get("name")

    def next_refs(o):
        t = o.get("type")
        if t == "attack-action":
            return o.get("effect_refs", []) or []
        if t == "attack-condition":
            return (o.get("on_true_refs", []) or []) + (o.get("on_false_refs", []) or [])
        if t == "attack-operator":
            return o.get("effect_refs", []) or []
        return []

    def dfs(node_id, acc, visited):
        if seen_cap[0] >= AF_MAX_PATHS_PER_FILE: return
        if node_id in visited: return
        o = by_id.get(node_id)
        if not o: return
        visited = visited | {node_id}
        if o.get("type") == "attack-action":
            nm = action_name(o)
            if nm: acc = acc + [nm]
        nbs = next_refs(o)
        if not nbs:
            if len(acc) >= MIN_CHAIN_LEN:
                paths.append(acc); seen_cap[0] += 1
            return
        for nb in nbs:
            if seen_cap[0] >= AF_MAX_PATHS_PER_FILE: break
            dfs(nb, acc, visited)

    for s in starts:
        if seen_cap[0] >= AF_MAX_PATHS_PER_FILE: break
        dfs(s, [], set())

    unique = list({tuple(seq) for seq in paths})
    return flow_name, [list(t) for t in unique]

def load_attack_flow_sequences(stix_dir, ATTACK_ID_TO_NAME):
    out = []
    if not os.path.isdir(stix_dir):
        log.warning(f"Attack Flow directory not found: {stix_dir}")
        return out
    files = sorted(glob.glob(os.path.join(stix_dir, "*.json")))
    log.info(f"Attack Flow: found {len(files)} JSON files in {stix_dir}.")
    for fp in tqdm(files, desc="Attack Flow STIX", leave=False):
        name, seqs = af_sequences_from_file(fp, ATTACK_ID_TO_NAME)
        for s in seqs:
            out.append(("AttackFlow", name, s))
    return out

def train_markov_from_sequences(json_sequences: List[List[str]]):
    start_counts = Counter()
    trans_counts = defaultdict(Counter)
    for seq in json_sequences:
        if not seq: continue
        start_counts[seq[0]] += 1
        for a,b in zip(seq[:-1], seq[1:]):
            trans_counts[a][b] += 1
    total_starts = sum(start_counts.values())
    start_prob = {k: (v/total_starts if total_starts else 0.0) for k,v in start_counts.items()}
    next_prob  = {}
    trans_total = 0
    for a, ctr in trans_counts.items():
        s = sum(ctr.values())
        next_prob[a] = {b: (c/s if s else 0.0) for b,c in ctr.items()}
        trans_total += len(ctr)
    return start_prob, next_prob, len(start_prob), trans_total

def markov_chain_prob(seq: List[str], start_prob: Dict[str,float], next_prob: Dict[str,Dict[str,float]]):
    if not seq: return 0.0
    p0 = max(start_prob.get(seq[0], MARKOV_MIN_PROB), MARKOV_MIN_PROB)
    logp = math.log(p0)
    for a,b in zip(seq[:-1], seq[1:]):
        p = next_prob.get(a, {}).get(b, MARKOV_MIN_PROB)
        logp += math.log(max(p, MARKOV_MIN_PROB))
    return math.exp(logp)

def expand_with_markov(prefix: List[str], start_prob, next_prob,
                       max_len=MARKOV_MAX_LEN, beam=MARKOV_BEAM, topk=MARKOV_TOPK_NEXT):
    BeamItem = Tuple[List[str], float]
    init_prob = markov_chain_prob(prefix, start_prob, next_prob)
    beam_list: List[BeamItem] = [(prefix[:], init_prob)]
    visited = set([tuple(prefix)])
    while True:
        extended: List[BeamItem] = []
        progressed = False
        for seq, p in beam_list:
            if len(seq) >= max_len:
                extended.append((seq, p)); continue
            last = seq[-1]
            nexts = sorted(next_prob.get(last, {}).items(), key=lambda kv: kv[1], reverse=True)[:topk]
            if not nexts:
                extended.append((seq, p)); continue
            for nb, prob in nexts:
                cand = seq + [nb]
                key = tuple(cand)
                if key in visited: continue
                visited.add(key); progressed = True
                extended.append((cand, p * max(prob, MARKOV_MIN_PROB)))
        if not progressed: break
        extended.sort(key=lambda x: x[1], reverse=True)
        beam_list = extended[:beam]
    return beam_list

def generate_markov_top_sequences(start_prob, next_prob, top_starts=20, beam=MARKOV_BEAM, topk=MARKOV_TOPK_NEXT, max_len=MARKOV_MAX_LEN):
    starts = sorted(start_prob.items(), key=lambda kv: kv[1], reverse=True)[:top_starts]
    all_out = []
    for s, _ in starts:
        beam_out = expand_with_markov([s], start_prob, next_prob, max_len=max_len, beam=beam, topk=topk)
        all_out.extend(beam_out)
    all_out.sort(key=lambda x: x[1], reverse=True)
    seen = set(); unique = []
    for seq, p in all_out:
        t = tuple(seq)
        if t in seen: continue
        seen.add(t); unique.append((seq, p))
    return unique

# =========================================================
# 1) Load MITRE ATT&CK Excel + maps + SEVERITY SCORES
# =========================================================
section("STEP 1) Load ATT&CK Excel & build technique/tactic maps")
assert os.path.exists(ATTACK_FILE), f"File not found: {ATTACK_FILE}"
read_kwargs = {}
if ATTACK_FILE.lower().endswith(".xls"):
    read_kwargs["engine"] = "xlrd"
else:
    read_kwargs["engine"] = "openpyxl"
t0 = time.time()
tech_df = pd.read_excel(ATTACK_FILE, sheet_name="techniques", **read_kwargs)
rel_df  = pd.read_excel(ATTACK_FILE, sheet_name="relationships", **read_kwargs)
camp_df = pd.read_excel(ATTACK_FILE, sheet_name="campaigns", **read_kwargs)
log.info(f"Loaded Excel sheets took {time.time()-t0:.2f}s")

campaign_severity = {}
if os.path.exists(SEVERITY_CSV):
    severity_df = pd.read_csv(SEVERITY_CSV)
    severity_df['NCISS_Normalized'] = severity_df['NCISS_Score'] / 10.0
    campaign_severity = dict(zip(severity_df['Campaign_ID'], severity_df['NCISS_Normalized']))
    log.info(f"Loaded {len(campaign_severity)} campaign severity scores from {SEVERITY_CSV}")
else:
    log.warning(f"Severity CSV not found: {SEVERITY_CSV}. Error analysis for 50/50 and 80/20 will be skipped.")

for col in ["ID","STIX ID","name","tactics"]:
    if col not in tech_df.columns:
        raise ValueError(f"'techniques' sheet missing column: {col}")

tech_df["tactics"] = tech_df["tactics"].fillna("").apply(
    lambda x: [t.strip() for t in x.split(",")] if isinstance(x, str) else []
)

rel_type_col = None
for c in rel_df.columns:
    if c.lower().strip() in ("relationship type","relationship_type","type"):
        rel_type_col = c; break

stix_to_name = dict(zip(tech_df["STIX ID"], tech_df["name"]))
id_to_name   = dict(zip(tech_df["ID"].astype(str), tech_df["name"]))
name_to_tactics = dict(zip(tech_df["name"], tech_df["tactics"]))

section("STEP 1a) Build sub-technique maps")
parent_to_subs = defaultdict(list)
sub_to_parent  = dict()
if rel_type_col is not None:
    for _, r in rel_df.iterrows():
        src, tgt = r.get("source ref",""), r.get("target ref","")
        rtype = str(r.get(rel_type_col,"")).lower()
        if not (isinstance(src, str) and isinstance(tgt, str)): continue
        if "attack-pattern--" in src and "attack-pattern--" in tgt and "subtechnique" in rtype:
            sub_name   = stix_to_name.get(src)
            parent_name= stix_to_name.get(tgt)
            if sub_name and parent_name:
                parent_to_subs[parent_name].append(sub_name)
                sub_to_parent[sub_name] = parent_name

tactics_flat = [t for lst in tech_df["tactics"] for t in lst]
tactic_order = [t.lower() for t in (TACTIC_ORDER_DEFAULT or sorted(set(tactics_flat), key=tactics_flat.index))]
log.info(f"Using tactic order (14): {', '.join(tactic_order)}")

def primary_tactic(name):
    tacs = name_to_tactics.get(name, [])
    return tacs[0].lower() if tacs else "unknown"

def is_subtech(name): return name in sub_to_parent
def parent_for(name):  return sub_to_parent.get(name, "")

# =========================================================
# 2) Generate chains from campaigns (pre-LSTM)
# =========================================================
section("STEP 2) Generate tactic-ordered attack chains from Campaigns (pre-LSTM)")

def techniques_for_campaign(stix_campaign_id: str):
    trefs = rel_df[
        (rel_df["source ref"] == stix_campaign_id) &
        (rel_df["target ref"].astype(str).str.startswith("attack-pattern--"))
    ]["target ref"].tolist()
    names = [stix_to_name.get(tid) for tid in trefs if tid in stix_to_name]
    expanded = set()
    for n in names:
        if n is None: continue
        expanded.add(n)
        for sub in parent_to_subs.get(n, []):
            expanded.add(sub)
    return list(expanded)

def bucket_by_tactic(names: list):
    buckets = {t: [] for t in tactic_order}
    for n in names:
        for tac in name_to_tactics.get(n, []):
            tkey = tac.lower()
            if tkey in buckets:
                buckets[tkey].append(n); break
    return [buckets[t] for t in tactic_order if buckets[t]]

def sample_perms(bucket: list, k: int):
    b = list(dict.fromkeys(bucket))
    if len(b) <= 1: return [tuple(b)]
    if len(b) <= 6: return list(islice(permutations(b), k))
    out = set(); trials = 0
    while len(out) < k and trials < k*20:
        sh = b[:]; random.shuffle(sh); out.add(tuple(sh)); trials += 1
    return list(out)

def generate_campaign_chains_for_row(row):
    stix_id = row["STIX ID"]
    names = techniques_for_campaign(stix_id)
    if not names: return []
    tactic_buckets = bucket_by_tactic(names)
    if not tactic_buckets: return []
    bucket_perms = [sample_perms(b, MAX_PERMS_PER_TACTIC) for b in tactic_buckets]
    chains = []
    for combo in islice(product(*bucket_perms), MAX_FULL_CHAINS_PER_CAMPAIGN):
        flat = [x for group in combo for x in group]
        if len(flat) >= MIN_CHAIN_LEN:
            chains.append(flat)
    return chains

t0 = time.time()
pre_chains, pre_camp_names, pre_camp_ids = [], [], []
for _, crow in tqdm(camp_df.iterrows(), total=len(camp_df), desc="Campaigns", leave=False):
    cs = generate_campaign_chains_for_row(crow)
    if cs:
        pre_chains.extend(cs)
        camp_name = crow.get("name","<unknown>")
        camp_id = crow.get("ID", "")
        pre_camp_names.extend([camp_name] * len(cs))
        pre_camp_ids.extend([camp_id] * len(cs))
log.info(f"Chain generation took {time.time()-t0:.2f}s")
log.info(f"Generated {len(pre_chains):,} chains from {len(set(pre_camp_names))} campaigns.")

section("STEP 2a) Save pre-LSTM chain catalogs")
pre_long_rows, pre_wide_rows = [], []
for cid, (camp_name, camp_id, chain) in enumerate(zip(pre_camp_names, pre_camp_ids, pre_chains), start=1):
    for step, name in enumerate(chain, start=1):
        pre_long_rows.append({
            "chain_id": cid,
            "campaign_id": camp_id,
            "campaign": camp_name,
            "step": step,
            "name": name,
            "tactic": primary_tactic(name),
            "is_subtech": int(is_subtech(name)),
            "parent_technique": parent_for(name)
        })
    pre_wide_rows.append({
        "chain_id": cid,
        "campaign_id": camp_id,
        "campaign": camp_name,
        "chain_length": len(chain),
        "chain": " -> ".join(chain)
    })
pre_long_df = pd.DataFrame(pre_long_rows)
pre_wide_df = pd.DataFrame(pre_wide_rows)
pre_long_csv = os.path.join(OUT_DIR, "pre_lstm_chains_long.csv")
pre_wide_csv = os.path.join(OUT_DIR, "pre_lstm_chains_wide.csv")
pre_xlsx     = os.path.join(OUT_DIR, "pre_lstm_chains.xlsx")
pre_long_df.to_csv(pre_long_csv, index=False)
pre_wide_df.to_csv(pre_wide_csv, index=False)
with pd.ExcelWriter(pre_xlsx, engine="xlsxwriter") as xlw:
    pre_wide_df.to_excel(xlw, index=False, sheet_name="Chains")
    pre_long_df.to_excel(xlw, index=False, sheet_name="Steps")
log.info(f"Saved:\n  {pre_wide_csv}\n  {pre_long_csv}\n  {pre_xlsx}")

# =========================================================
# 3) Train LSTM on pre-LSTM chains + score (post-LSTM)
# =========================================================
section("STEP 3) LSTM training on pre-LSTM chains + post-LSTM scoring")

all_chains = list(pre_chains)
campaign_index = list(pre_camp_names)
campaign_ids_index = list(pre_camp_ids)

vocab = sorted({n for seq in all_chains for n in seq})
stoi = {s:i+1 for i,s in enumerate(vocab)}
itos = {i:s for s,i in stoi.items()}

def encode(seq):  return torch.tensor([stoi[s] for s in seq if s in stoi], dtype=torch.long)
encoded = [encode(s) for s in all_chains if len(s) >= MIN_CHAIN_LEN]

def make_training_pairs(seqs, max_len=50):
    X, Y = [], []
    for t in seqs:
        for i in range(1, len(t)):
            start = max(0, i - max_len)
            X.append(t[start:i]); Y.append(t[i])
    return X, Y

X_list, Y_list = make_training_pairs(encoded, max_len=50)
log.info(f"Vocab size: {len(vocab):,} | Chains: {len(all_chains):,} | Training pairs: {len(X_list):,}")

class ChainDataset(Dataset):
    def __init__(self, X, Y): self.X, self.Y = X, Y
    def __len__(self): return len(self.X)
    def __getitem__(self, i): return self.X[i], self.Y[i]

def collate(batch):
    xs, ys = zip(*batch)
    lengths = torch.tensor([len(x) for x in xs], dtype=torch.long)
    padded = nn.utils.rnn.pad_sequence(xs, batch_first=True, padding_value=0)
    return padded, torch.tensor(ys, dtype=torch.long), lengths

perm = np.random.permutation(len(X_list))
cut = int(0.9 * len(perm))
train_idx, val_idx = perm[:cut], perm[cut:]
train_ds = ChainDataset([X_list[i] for i in train_idx], [Y_list[i] for i in train_idx])
val_ds   = ChainDataset([X_list[i] for i in val_idx], [Y_list[i] for i in val_idx])

train_loader = DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True, collate_fn=collate)
val_loader   = DataLoader(val_ds,   batch_size=BATCH_SIZE, shuffle=False, collate_fn=collate)

class NextStepLSTM(nn.Module):
    def __init__(self, vocab_size, emb=EMBED_DIM, hid=HIDDEN_DIM, layers=NUM_LAYERS, dropout=DROPOUT):
        super().__init__()
        self.emb = nn.Embedding(vocab_size+1, emb, padding_idx=0)
        self.lstm = nn.LSTM(emb, hid, num_layers=layers, dropout=dropout, batch_first=True)
        self.proj = nn.Linear(hid, vocab_size+1)
    def forward(self, x, lengths):
        e = self.emb(x)
        packed = nn.utils.rnn.pack_padded_sequence(e, lengths.cpu(), batch_first=True, enforce_sorted=False)
        _, (hn, _) = self.lstm(packed)
        last = hn[-1]
        logits = self.proj(last)
        return logits

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model = NextStepLSTM(vocab_size=len(vocab)).to(device)
opt = torch.optim.AdamW(model.parameters(), lr=LR)
loss_fn = nn.CrossEntropyLoss()
log.info(f"Device: {device} | Params: {sum(p.numel() for p in model.parameters()):,}")

train_losses, val_losses, train_accs, val_accs = [], [], [], []
def run_epoch(loader, train=True, epoch_idx=0, total_epochs=0):
    model.train(train)
    total, correct, loss_sum = 0, 0, 0.0
    pbar = tqdm(loader, desc=f"{'Train' if train else 'Val'} E{epoch_idx}/{total_epochs}", leave=False)
    for step, (xb, yb, lb) in enumerate(pbar, start=1):
        xb, yb, lb = xb.to(device), yb.to(device), lb.to(device)
        logits = model(xb, lb)
        loss = loss_fn(logits, yb)
        if train:
            opt.zero_grad(); loss.backward(); opt.step()
        with torch.no_grad():
            preds = logits.argmax(dim=-1)
            correct += (preds == yb).sum().item()
            total += yb.numel()
            loss_sum += loss.item() * yb.numel()
        if step % TRAIN_PROGRESS_EVERY == 0:
            pbar.set_postfix(loss=f"{loss.item():.4f}", acc=f"{(correct/total):.3f}")
    return (loss_sum/total if total else 0.0), (correct/total if total else 0.0)

t0 = time.time()
for epoch in range(1, EPOCHS+1):
    tr_loss, tr_acc = run_epoch(train_loader, True, epoch, EPOCHS)
    va_loss, va_acc = run_epoch(val_loader, False, epoch, EPOCHS)
    train_losses.append(tr_loss); val_losses.append(va_loss)
    train_accs.append(tr_acc);   val_accs.append(va_acc)
    log.info(f"Epoch {epoch:02d}/{EPOCHS} | train loss {tr_loss:.4f} acc {tr_acc:.3f} | val loss {va_loss:.4f} acc {va_acc:.3f}")
log.info(f"Training complete took {time.time()-t0:.2f}s")

@torch.no_grad()
def chain_prob_lstm(seq_names: List[str]) -> float:
    logp = 0.0
    for i in range(1, len(seq_names)):
        prefix = seq_names[:i]
        target = seq_names[i]
        prefix_ids = [stoi[s] for s in prefix if s in stoi]
        target_id = stoi.get(target, None)
        if len(prefix_ids) == 0 or target_id is None:
            logp += math.log(MARKOV_MIN_PROB); continue
        t = torch.tensor(prefix_ids, dtype=torch.long).unsqueeze(0).to(device)
        l = torch.tensor([len(prefix_ids)], dtype=torch.long).to(device)
        logits = model(t, l).squeeze(0)
        probs = torch.softmax(logits, dim=-1)
        p = max(probs[target_id].item(), MARKOV_MIN_PROB)
        logp += math.log(p)
    return math.exp(logp)

def geometric_mean_prob(ps):
    if not ps: return 0.0
    return math.exp(sum(math.log(max(p,MARKOV_MIN_PROB)) for p in ps) / len(ps))

section("STEP 3a) Score & save POST-LSTM chains (probability + per-step risk)")

EPSS = defaultdict(lambda: None)
CAPEC_LIKELIHOOD = defaultdict(lambda: None)
KEV_FLAG = defaultdict(lambda: 0)
DETECTION_COVERAGE = defaultdict(lambda: 0.0)

def try_load_csv_map(path, key_col_candidates, val_col_candidates, cast=float, default=None):
    if not path or not os.path.exists(path): return {}
    df = pd.read_csv(path)
    cols = {c.lower(): c for c in df.columns}
    key_col = next((cols[c] for c in [k.lower() for k in key_col_candidates] if c in cols), None)
    val_col = next((cols[c] for c in [v.lower() for v in val_col_candidates] if c in cols), None)
    if key_col is None or val_col is None:
        log.warning(f"Could not find expected columns in {path}. Skipping.")
        return {}
    out = {}
    for _, r in df.iterrows():
        k = str(r[key_col]).strip()
        v = r[val_col]
        try: out[k] = cast(v)
        except Exception: out[k] = default
    return out

for k,v in try_load_csv_map(EPSS_CSV, ["technique","name"], ["epss","score"], float, None).items(): EPSS[k]=v
for k,v in try_load_csv_map(KEV_CSV,  ["technique","name"], ["kev","is_kev","flag"], int, 0).items(): KEV_FLAG[k]=v
for k,v in try_load_csv_map(DETECTION_CSV, ["technique","name"], ["coverage","detect","d3fend"], float, 0.0).items(): DETECTION_COVERAGE[k]=v

def step_likelihood(name, modeled_next_prob=None):
    base = None
    if EPSS[name] is not None:
        base = EPSS[name]
    elif CAPEC_LIKELIHOOD[name] is not None:
        base = CAPEC_LIKELIHOOD[name]
    elif modeled_next_prob is not None:
        base = modeled_next_prob
    else:
        base = 0.1
    if KEV_FLAG[name]:
        base = min(1.0, base + 0.1)
    return float(base)

def step_detectability(name):
    cov = min(max(float(DETECTION_COVERAGE[name]), 0.0), 1.0)
    return 1.0 - cov

@torch.no_grad()
def score_chain(seq_names, octave_impact_0_10=OCTAVE_IMPACT_0_10_DEFAULT):
    modeled_next = []
    for i in range(1, len(seq_names)):
        prefix = seq_names[:i]
        target = seq_names[i]
        prefix_ids = [stoi[s] for s in prefix if s in stoi]
        target_id = stoi.get(target, None)
        if len(prefix_ids) == 0 or target_id is None:
            modeled_next.append(None); continue
        t = torch.tensor(prefix_ids, dtype=torch.long).unsqueeze(0).to(device)
        l = torch.tensor([len(prefix_ids)], dtype=torch.long).to(device)
        logits = model(t, l).squeeze(0)
        probs = torch.softmax(logits, dim=-1).cpu().numpy()
        modeled_next.append(float(probs[target_id]))
    per_step_scores, per_step_likes, per_step_detect = [], [], []
    for i, name in enumerate(seq_names):
        modeled_prob = modeled_next[i-1] if i > 0 and i-1 < len(modeled_next) else None
        like = step_likelihood(name, modeled_prob)
        det  = step_detectability(name)
        per_step_likes.append(like); per_step_detect.append(det); per_step_scores.append(like*det)
    chain_like = max(MARKOV_MIN_PROB, min(1.0, geometric_mean_prob([max(p,MARKOV_MIN_PROB) for p in per_step_likes if p is not None and p > 0.0])))
    final_risk = 10.0 * chain_like * (float(octave_impact_0_10) / 10.0)
    final_risk = min(10.0, final_risk)
    return {
        "per_step_scores": per_step_scores,
        "per_step_likelihoods": per_step_likes,
        "per_step_detectability": per_step_detect,
        "chain_geomean_likelihood": chain_like,
        "octave_impact_0_10": float(octave_impact_0_10),
        "final_risk_score_0_10": float(final_risk)
    }

post_rows = []
for cid, (camp_id, camp_name, chain) in enumerate(zip(campaign_ids_index, campaign_index, all_chains), start=1):
    prob_lstm = chain_prob_lstm(chain)
    rs = score_chain(chain, OCTAVE_IMPACT_0_10_DEFAULT)
    post_rows.append({
        "chain_id": cid,
        "campaign_id": camp_id,
        "campaign": camp_name,
        "chain_length": len(chain),
        "chain": " -> ".join(chain),
        "lstm_chain_probability": prob_lstm,
        "chain_geomean_likelihood": rs["chain_geomean_likelihood"],
        "final_risk_score_0_10": rs["final_risk_score_0_10"],
        "per_step_likelihoods": json.dumps(rs["per_step_likelihoods"]),
        "per_step_detectability": json.dumps(rs["per_step_detectability"]),
        "per_step_scores": json.dumps(rs["per_step_scores"]),
        "octave_impact_0_10": rs["octave_impact_0_10"]
    })
post_df = pd.DataFrame(post_rows)
post_csv = os.path.join(OUT_DIR, "post_lstm_chains_scored.csv")
post_xlsx = os.path.join(OUT_DIR, "post_lstm_chains_scored.xlsx")
post_df.to_csv(post_csv, index=False)
with pd.ExcelWriter(post_xlsx, engine="xlsxwriter") as xlw:
    post_df.to_excel(xlw, index=False, sheet_name="Chains+Scores")
post_sorted = post_df.sort_values(["final_risk_score_0_10","lstm_chain_probability"], ascending=[False,False])
post_sorted.to_csv(os.path.join(OUT_DIR,"post_lstm_chains_scored_sorted.csv"), index=False)

log.info(f"Saved POST-LSTM catalogs:\n  {post_csv}\n  {post_xlsx}")

section("STEP 3b) Terminal: Top chains by probability and risk")
if not post_df.empty:
    top_prob = post_df.sort_values("lstm_chain_probability", ascending=False).head(5)
    top_risk = post_df.sort_values("final_risk_score_0_10", ascending=False).head(5)
    log.info("\nTop-5 by Probability:")
    for _, r in top_prob.iterrows():
        log.info(f" P={r['lstm_chain_probability']:.3e} | Len={int(r['chain_length'])} | Camp={r['campaign']} | {r['chain'][:140]}")
    log.info("\nTop-5 by Risk:")
    for _, r in top_risk.iterrows():
        log.info(f" RISK={r['final_risk_score_0_10']:.2f} | like={r['chain_geomean_likelihood']:.3f} | Camp={r['campaign']} | {r['chain'][:140]}")

section("STEP 3c) Visualizations")
if len(train_losses):
    plt.figure(); plt.plot(range(1,EPOCHS+1), train_losses, marker="o", label="train loss")
    plt.plot(range(1,EPOCHS+1), val_losses, marker="o", label="val loss")
    plt.xlabel("Epoch"); plt.ylabel("Loss"); plt.title("LSTM Loss"); plt.legend()
    save_fig(os.path.join(OUT_DIR, "plot_lstm_loss.png"))
if len(train_accs):
    plt.figure(); plt.plot(range(1,EPOCHS+1), train_accs, marker="o", label="train acc")
    plt.plot(range(1,EPOCHS+1), val_accs, marker="o", label="val acc")
    plt.xlabel("Epoch"); plt.ylabel("Accuracy"); plt.title("LSTM Accuracy"); plt.legend()
    save_fig(os.path.join(OUT_DIR, "plot_lstm_acc.png"))

# =========================================================
# 4) Ingest Unit42 + Attack Flow
# =========================================================
section("STEP 4) Ingest Unit42 Playbooks + Attack Flow JSON -> chains")
ATTACK_ID_TO_NAME = dict(zip(tech_df["ID"].astype(str), tech_df["name"]))

external_entries = []
if os.path.isdir(UNIT42_REPO_DIR):
    external_entries.extend(load_unit42_sequences(UNIT42_REPO_DIR, tactic_order, ATTACK_ID_TO_NAME))
else:
    log.warning(f"Unit42 path not found: {UNIT42_REPO_DIR}")

if os.path.isdir(ATTACK_FLOW_STIX_DIR):
    external_entries.extend(load_attack_flow_sequences(ATTACK_FLOW_STIX_DIR, ATTACK_ID_TO_NAME))
else:
    log.warning(f"Attack Flow dir not found: {ATTACK_FLOW_STIX_DIR}")

if external_entries:
    ext_rows = [{"source": src, "document": doc, "chain_length": len(seq), "chain": " -> ".join(seq)} for (src, doc, seq) in external_entries]
    ext_df = pd.DataFrame(ext_rows)
    ext_csv = os.path.join(OUT_DIR, "external_sequences.csv")
    ext_df.to_csv(ext_csv, index=False)
    log.info(f"Saved external sequences CSV: {ext_csv}")
else:
    log.warning("No external sequences found (check local paths).")

# =========================================================
# 5) Train Markov
# =========================================================
section("STEP 5) Train first-order Markov model on JSON-derived chains (pre-Markov)")
json_only = [seq for (_,_,seq) in external_entries]
log.info(f"JSON-derived chains (Unit42 + Attack Flow): {len(json_only):,}")
start_prob, next_prob, start_states, unique_transitions = train_markov_from_sequences(json_only)

markov_model_path = os.path.join(OUT_DIR, "markov_model.json")
with open(markov_model_path, "w", encoding="utf-8") as f:
    json.dump({"start_prob": start_prob, "next_prob": next_prob}, f, indent=2)
log.info(f"Saved Markov model: {markov_model_path}")
log.info(f"Markov states: {start_states} | Unique transitions: {unique_transitions:,}")

top_markov = generate_markov_top_sequences(start_prob, next_prob, top_starts=30, beam=MARKOV_BEAM, topk=MARKOV_TOPK_NEXT, max_len=MARKOV_MAX_LEN)
mk_top_rows = [{"chain_length": len(seq), "chain": " -> ".join(seq), "markov_chain_probability": p} for (seq,p) in top_markov[:300]]
mk_top_df = pd.DataFrame(mk_top_rows)
mk_top_csv = os.path.join(OUT_DIR, "markov_top_sequences.csv")
mk_top_xlsx= os.path.join(OUT_DIR, "markov_top_sequences.xlsx")
mk_top_df.to_csv(mk_top_csv, index=False)
with pd.ExcelWriter(mk_top_xlsx, engine="xlsxwriter") as xlw:
    mk_top_df.to_excel(xlw, index=False, sheet_name="MarkovTop")
log.info("Saved pre-Markov predictions:\n  " + mk_top_csv + "\n  " + mk_top_xlsx)

# =========================================================
# 6) Validate Markov
# =========================================================
section("STEP 6) Validate Markov with POST-LSTM chains (probabilities out of 1)")

val_rows = []
for cid, (camp, chain) in enumerate(zip(campaign_index, all_chains), start=1):
    mk_p = markov_chain_prob(chain, start_prob, next_prob)
    trans = list(zip(chain[:-1], chain[1:]))
    cov = (sum(1 for (a,b) in trans if b in next_prob.get(a, {})) / len(trans)) if trans else 0.0
    val_rows.append({
        "chain_id": cid,
        "campaign": camp,
        "chain_length": len(chain),
        "coverage": round(cov, 4),
        "markov_chain_probability": mk_p,
        "lstm_chain_probability": chain_prob_lstm(chain),
        "chain": " -> ".join(chain)
    })
val_df = pd.DataFrame(val_rows)
val_csv = os.path.join(OUT_DIR, "validation_lstm_vs_markov.csv")
val_xlsx= os.path.join(OUT_DIR, "validation_lstm_vs_markov.xlsx")
val_df.to_csv(val_csv, index=False)
with pd.ExcelWriter(val_xlsx, engine="xlsxwriter") as xlw:
    val_df.to_excel(xlw, index=False, sheet_name="Validation")
log.info("Saved LSTM vs Markov validation tables:\n  " + val_csv + "\n  " + val_xlsx)

# =========================================================
# 6b) Post-Markov expansions
# =========================================================
section("STEP 6b) Post-Markov expansions (streaming, memory-safe)")

post_mk_stream_csv = os.path.join(OUT_DIR, "post_markov_expansions_stream.csv")
stream_cols = [
    "orig_chain_id","orig_prefix","chain_length","chain",
    "markov_chain_probability","lstm_chain_probability",
    "chain_geomean_likelihood","final_risk_score_0_10"
]

if SKIP_POST_MARKOV_EXPANSION:
    log.warning("SKIP_POST_MARKOV_EXPANSION=1 -> skipping Step 6b expansions.")
else:
    total_to_expand = min(len(all_chains), POST_MARKOV_MAX_CHAINS)
    log.info(f"Expanding Markov from {total_to_expand} LSTM chains "
             f"(seed len={POST_MARKOV_EXPAND_SEED_LEN}, beam={MARKOV_BEAM}, topk={MARKOV_TOPK_NEXT}).")

    with open(post_mk_stream_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=stream_cols)
        writer.writeheader()

    rows_written = 0
    t_start = time.time()
    for chain_id, chain in enumerate(all_chains[:total_to_expand], start=1):
        if ABORT[0]:
            log.warning("Abort requested; stopping expansion loop.")
            break

        mk_prob = markov_chain_prob(chain, start_prob, next_prob)
        sl = POST_MARKOV_EXPAND_SEED_LEN
        seed = chain[:sl] if len(chain) >= sl else chain[:]

        expansions = expand_with_markov(
            seed, start_prob, next_prob,
            max_len=min(MARKOV_MAX_LEN, len(chain)+5),
            beam=MARKOV_BEAM, topk=MARKOV_TOPK_NEXT
        )

        candidates = [(chain, mk_prob)] + expansions

        with open(post_mk_stream_csv, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=stream_cols)
            for seq, p_mk in candidates:
                rs = score_chain(seq, OCTAVE_IMPACT_0_10_DEFAULT)
                writer.writerow({
                    "orig_chain_id": chain_id,
                    "orig_prefix": " -> ".join(seed),
                    "chain_length": len(seq),
                    "chain": " -> ".join(seq),
                    "markov_chain_probability": float(p_mk),
                    "lstm_chain_probability": float(chain_prob_lstm(seq)),
                    "chain_geomean_likelihood": rs["chain_geomean_likelihood"],
                    "final_risk_score_0_10": rs["final_risk_score_0_10"]
                })
                rows_written += 1

        if chain_id % POST_MARKOV_LOG_EVERY == 0:
            elapsed = time.time() - t_start
            log.info(f"  Expanded {chain_id}/{total_to_expand} chains; wrote {rows_written} rows in {elapsed:.1f}s")

    log.info(f"Post-Markov streaming expansions complete. Total rows: {rows_written}. "
             f"CSV: {post_mk_stream_csv}")

if os.path.exists(post_mk_stream_csv):
    post_mk_df = pd.read_csv(post_mk_stream_csv)
else:
    post_mk_df = pd.DataFrame(columns=stream_cols)

# =========================================================
# 7) Score Markov sequences
# =========================================================
section("STEP 7) Score Markov top sequences with per-step probabilities and per-step risk (0–10)")
if not post_mk_df.empty:
    post_mk_sorted = post_mk_df.sort_values(
        ["final_risk_score_0_10","markov_chain_probability"],
        ascending=[False, False]
    )
else:
    post_mk_sorted = post_mk_df.copy()

mk_scored_csv  = os.path.join(OUT_DIR, "markov_top_sequences_scored.csv")
mk_scored_xlsx = os.path.join(OUT_DIR, "markov_top_sequences_scored.xlsx")
post_mk_sorted.to_csv(mk_scored_csv, index=False)
with pd.ExcelWriter(mk_scored_xlsx, engine="xlsxwriter") as xlw:
    post_mk_sorted.to_excel(xlw, index=False, sheet_name="PostMarkov+Scores")
log.info("Saved post-Markov sequences with probability + risk:\n  " + mk_scored_csv + "\n  " + mk_scored_xlsx)

if not post_mk_sorted.empty:
    plt.figure()
    x = post_mk_sorted["chain_geomean_likelihood"].values
    y = post_mk_sorted["final_risk_score_0_10"].values
    plt.scatter(x, y, s=10)
    plt.xlabel("Geometric-Mean Likelihood"); plt.ylabel("Final Risk (0–10)")
    plt.title("Risk vs Likelihood (Post-Markov)")
    save_fig(os.path.join(OUT_DIR, "plot_risk_vs_likelihood_post_markov.png"))

# =========================================================
# 8) Dataset mapping
# =========================================================
section("STEP 8) Dataset mapping -> chain filtering + scoring")

LABEL_TO_ATTACK = {
    "Benign": [],
    "Port Scan": ["Network Service Discovery"],
    "OS Scan":   ["System Information Discovery"],
    "Ping Sweep":["Network Service Discovery"],
    "HTTP Flood":["Network DoS"],
    "UDP Flood": ["Network DoS"],
    "TCP SYN":   ["Network DoS"],
    "Slowloris": ["Application Layer Protocol"],
    "Dictionary Attack": ["Brute Force"],
    "ARP Spoofing": ["Adversary-in-the-Middle"],
    "DoS": ["Network DoS"],
    "PortScan": ["Network Service Discovery"],
    "DDoS": ["Network DoS"],
    "BruteForce": ["Brute Force"],
    "WebAttack": ["Exploitation for Client Execution"],
    "Botnet": ["Command and Control"],
    "Infiltration": ["Exploitation for Privilege Escalation"]
}

def load_dataset_labels(csv_path: str, label_col: str) -> List[str]:
    if not csv_path or not os.path.exists(csv_path): return []
    df = pd.read_csv(csv_path)
    if label_col not in df.columns:
        alt = [c for c in df.columns if c.lower() == label_col.lower()]
        if not alt: raise ValueError(f"Label column '{label_col}' not found")
        label_col = alt[0]
    return list(df[label_col].astype(str).values)

dataset_labels = load_dataset_labels(DATASET_PATH, DATASET_LABEL)
log.info(f"Loaded dataset labels: {len(dataset_labels)} rows")

def chains_containing_any(attacks: List[str], universe_df: pd.DataFrame, chain_col="chain") -> pd.DataFrame:
    if not attacks: return universe_df.copy()
    pat = r"|".join(re.escape(a) for a in attacks)
    return universe_df[universe_df[chain_col].str.contains(pat, na=False)]

universe = post_mk_sorted.copy()
universe["rank"] = range(1, len(universe)+1)

filtered_rows = []
if dataset_labels:
    label_counts = Counter(dataset_labels)
    for label, freq in label_counts.items():
        attacks = LABEL_TO_ATTACK.get(label, [])
        sub = chains_containing_any(attacks, universe)
        sub = sub.copy()
        sub["dataset_label"] = label
        sub["label_frequency"] = freq
        filtered_rows.append(sub)

if filtered_rows:
    result_df = pd.concat(filtered_rows, ignore_index=True)
    lbl_csv = os.path.join(OUT_DIR, "dataset_label_filtered_chains.csv")
    result_df.to_csv(lbl_csv, index=False)
    log.info(f"Saved dataset-filtered chains: {lbl_csv}")
    tops = result_df.sort_values(
        ["dataset_label","final_risk_score_0_10","markov_chain_probability"],
        ascending=[True, False, False]
    ).groupby("dataset_label").head(50)
    tops_csv = os.path.join(OUT_DIR, "dataset_label_top50_per_label.csv")
    tops.to_csv(tops_csv, index=False)
    log.info(f"Saved per-label Top-50 chains: {tops_csv}")
else:
    log.info("No dataset mapping executed (set DATASET_PATH & DATASET_LABEL to enable Step 8).")

# =========================================================
# 8b) Dataset-anchored predictions
# =========================================================
section("STEP 8b) Dataset-anchored predictive chains & next-step probabilities")

CICIDS_TO_ATTACK = {
    "benign": [],
    "portscan": ["Network Service Discovery"],
    "infiltration": ["Exploitation for Privilege Escalation"],
    "botnet": ["Command and Control"],
    "ddos": ["Network DoS"],
    "dos": ["Network DoS"],
    "dos hulk": ["Network DoS"],
    "dos goldeneye": ["Network DoS"],
    "dos slowloris": ["Application Layer Protocol", "Network DoS"],
    "dos slowhttptest": ["Application Layer Protocol", "Network DoS"],
    "bruteforce": ["Brute Force"],
    "ftp-patator": ["Brute Force"],
    "ssh-patator": ["Brute Force"],
    "web attack - brute force": ["Brute Force"],
    "web attack - xss": ["Exploitation for Client Execution"],
    "web attack - sql injection": ["Exploitation of Public-Facing Application"],
    "heartbleed": ["Exploit Public-Facing Application"],
    "bot": ["Command and Control"],
    "xss": ["Exploitation for Client Execution"],
    "sql injection": ["Exploitation of Public-Facing Application"],
    "dictionary attack": ["Brute Force"],
    "arp spoofing": ["Adversary-in-the-Middle"],
    "icmp flood": ["Network DoS"],
    "udp flood": ["Network DoS"],
    "tcp syn": ["Network DoS"],
}

def map_label_to_attacks_generic(label: str) -> list:
    if not isinstance(label, str): return []
    if label in LABEL_TO_ATTACK:
        return LABEL_TO_ATTACK[label]
    l = label.strip().lower()
    if l in CICIDS_TO_ATTACK:
        return CICIDS_TO_ATTACK[l]
    if "xss" in l: return ["Exploitation for Client Execution"]
    if "sql" in l and "inject" in l: return ["Exploitation of Public-Facing Application"]
    if "ddos" in l: return ["Network DoS"]
    if "dos" in l: return ["Network DoS"]
    if "brute" in l: return ["Brute Force"]
    if "patator" in l: return ["Brute Force"]
    if "port" in l and "scan" in l: return ["Network Service Discovery"]
    if "bot" in l: return ["Command and Control"]
    if "infiltrat" in l: return ["Exploitation for Privilege Escalation"]
    if "slowloris" in l: return ["Application Layer Protocol", "Network DoS"]
    if "arp" in l and "spoof" in l: return ["Adversary-in-the-Middle"]
    return []

def extract_attack_types_from_dataset(labels: list) -> dict:
    out = {}
    for lab in sorted(set(labels)):
        mapped = LABEL_TO_ATTACK.get(lab, None)
        if mapped is None:
            mapped = map_label_to_attacks_generic(lab)
        out[lab] = sorted(set(mapped))
    return out

def markov_per_step_probs(seq: List[str], start_prob, next_prob) -> List[float]:
    if not seq: return []
    out = [max(start_prob.get(seq[0], MARKOV_MIN_PROB), MARKOV_MIN_PROB)]
    for a, b in zip(seq[:-1], seq[1:]):
        out.append(max(next_prob.get(a, {}).get(b, MARKOV_MIN_PROB), MARKOV_MIN_PROB))
    return out

def produce_anchor_predictions_for_tech(anchor_tech: str,
                                        start_prob, next_prob,
                                        max_len=MARKOV_MAX_LEN,
                                        beam=MARKOV_BEAM,
                                        topk=MARKOV_TOPK_NEXT,
                                        limit_per_anchor=200) -> pd.DataFrame:
    beam_out = expand_with_markov([anchor_tech], start_prob, next_prob,
                                  max_len=max_len, beam=beam, topk=topk)
    beam_out = beam_out[:limit_per_anchor] if limit_per_anchor else beam_out
    rows = []
    for seq, p_mk in beam_out:
        per_step = markov_per_step_probs(seq, start_prob, next_prob)
        p_lstm = chain_prob_lstm(seq)
        rs = score_chain(seq, OCTAVE_IMPACT_0_10_DEFAULT)
        rows.append({
            "anchor_technique": anchor_tech,
            "chain_length": len(seq),
            "chain": " -> ".join(seq),
            "markov_chain_probability": float(p_mk),
            "markov_per_step_probs": json.dumps(per_step),
            "lstm_chain_probability": float(p_lstm),
            "chain_geomean_likelihood": rs["chain_geomean_likelihood"],
            "final_risk_score_0_10": rs["final_risk_score_0_10"]
        })
    return pd.DataFrame(rows)

if dataset_labels:
    label_to_attacks = extract_attack_types_from_dataset(dataset_labels)

    map_rows = [{"dataset_label": lab, "mapped_attack_techniques": "; ".join(attacks)}
                for lab, attacks in label_to_attacks.items()]
    map_df = pd.DataFrame(map_rows).sort_values("dataset_label")
    mapping_csv = os.path.join(OUT_DIR, "dataset_label_to_attack_mapping.csv")
    map_df.to_csv(mapping_csv, index=False)
    log.info(f"Saved dataset→ATT&CK mapping: {mapping_csv}")

    anchor_existing_rows = []
    for lab, attacks in label_to_attacks.items():
        for atk in attacks:
            if not atk: continue
            sub = post_mk_sorted[post_mk_sorted["chain"].str.contains(re.escape(atk), na=False)].copy()
            if sub.empty: continue
            sub.insert(0, "dataset_label", lab)
            sub.insert(1, "anchor_technique", atk)
            anchor_existing_rows.append(sub)
    if anchor_existing_rows:
        existing_df = pd.concat(anchor_existing_rows, ignore_index=True)
        existing_df = existing_df.sort_values(
            ["dataset_label","final_risk_score_0_10","markov_chain_probability"],
            ascending=[True, False, False]
        )
        existing_csv = os.path.join(OUT_DIR, "dataset_anchor_existing_chains.csv")
        existing_df.to_csv(existing_csv, index=False)
        log.info(f"Saved existing chains containing dataset attack types: {existing_csv}")
    else:
        log.info("No existing chains matched any dataset attack types.")

    anchor_pred_dfs = []
    nextstep_rows = []
    for lab, attacks in label_to_attacks.items():
        for atk in attacks:
            if not atk: continue
            nexts = sorted(next_prob.get(atk, {}).items(), key=lambda kv: kv[1], reverse=True)[:20]
            for nb, p in nexts:
                nextstep_rows.append({
                    "dataset_label": lab,
                    "anchor_technique": atk,
                    "next_technique": nb,
                    "markov_next_prob": float(p)
                })
            df_pred = produce_anchor_predictions_for_tech(
                atk, start_prob, next_prob,
                max_len=min(MARKOV_MAX_LEN, 20),
                beam=MARKOV_BEAM, topk=MARKOV_TOPK_NEXT,
                limit_per_anchor=300
            )
            if not df_pred.empty:
                df_pred.insert(0, "dataset_label", lab)
                anchor_pred_dfs.append(df_pred)

    if nextstep_rows:
        nextstep_df = pd.DataFrame(nextstep_rows).sort_values(
            ["dataset_label","anchor_technique","markov_next_prob"], ascending=[True, True, False]
        )
        nextstep_csv = os.path.join(OUT_DIR, "dataset_anchor_nextstep_probs.csv")
        nextstep_df.to_csv(nextstep_csv, index=False)
        log.info(f"Saved next-step probabilities for each anchor: {nextstep_csv}")

    if anchor_pred_dfs:
        preds_df = pd.concat(anchor_pred_dfs, ignore_index=True)
        preds_df = preds_df.sort_values(
            ["dataset_label","final_risk_score_0_10","markov_chain_probability"],
            ascending=[True, False, False]
        )
        preds_csv = os.path.join(OUT_DIR, "dataset_anchor_predicted_chains.csv")
        preds_xlsx = os.path.join(OUT_DIR, "dataset_anchor_predicted_chains.xlsx")
        preds_df.to_csv(preds_csv, index=False)
        with pd.ExcelWriter(preds_xlsx, engine="xlsxwriter") as xlw:
            preds_df.to_excel(xlw, index=False, sheet_name="Predictions")
        log.info(f"Saved dataset-anchored predictive chains:\n  {preds_csv}\n  {preds_xlsx}")

        tops = (
            preds_df
            .groupby(["dataset_label","anchor_technique"], as_index=False, group_keys=False)
            .apply(lambda g: g.head(100))
        )
        tops_csv = os.path.join(OUT_DIR, "dataset_anchor_top100_per_anchor.csv")
        tops.to_csv(tops_csv, index=False)
        log.info(f"Saved Top-100 per anchor: {tops_csv}")
    else:
        log.info("No predictive anchor chains were generated (check mapping or Markov transitions).")
else:
    log.info("Dataset labels not provided or empty; STEP 8b skipped. Set DATASET_PATH / DATASET_LABEL to enable.")

# =========================================================
# Additional Visualizations
# =========================================================
section("Additional Visualizations for Research Paper")

log.info("Risk vs Likelihood scatter plot already saved as plot_risk_vs_likelihood_post_markov.png")

if not post_df.empty:
    plt.figure(figsize=(8, 6))
    plt.hist(post_df['chain_length'], bins=25, edgecolor='black', alpha=0.7, color='steelblue')
    plt.xlabel('Chain Length (Number of Techniques)', fontsize=12)
    plt.ylabel('Frequency (Number of Chains)', fontsize=12)
    plt.title('Distribution of Attack Chain Lengths (Pre-LSTM Chains)', fontsize=14)
    plt.grid(axis='y', alpha=0.3)
    save_fig(os.path.join(OUT_DIR, "plot_chain_length_distribution.png"))
    log.info("Saved chain length distribution histogram")

if not post_mk_sorted.empty:
    plt.figure(figsize=(8, 6))
    plt.hist(post_mk_sorted['final_risk_score_0_10'], bins=30, edgecolor='black', 
             alpha=0.7, color='crimson')
    plt.xlabel('Risk Score (0-10 scale)', fontsize=12)
    plt.ylabel('Frequency (Number of Predictions)', fontsize=12)
    plt.title(f'Distribution of Risk Scores Across {len(post_mk_sorted):,} Predictions', fontsize=14)
    plt.axvline(x=7.0, color='orange', linestyle='--', linewidth=2, label='High risk threshold (7.0)')
    plt.axvline(x=post_mk_sorted['final_risk_score_0_10'].mean(), color='green', 
                linestyle='--', linewidth=2, label=f'Mean: {post_mk_sorted["final_risk_score_0_10"].mean():.2f}')
    plt.legend()
    plt.grid(axis='y', alpha=0.3)
    save_fig(os.path.join(OUT_DIR, "plot_risk_score_distribution.png"))
    log.info("Saved risk score distribution histogram")

if os.path.exists(val_csv):
    val_df_viz = pd.read_csv(val_csv)
    plt.figure(figsize=(8, 6))
    plt.hist(val_df_viz['coverage'], bins=30, edgecolor='black', alpha=0.7, color='mediumseagreen')
    plt.xlabel('Markov Coverage (Fraction of Transitions)', fontsize=12)
    plt.ylabel('Frequency (Number of Chains)', fontsize=12)
    plt.title(f'LSTM-Markov Coverage Distribution ({len(val_df_viz):,} Chains)', fontsize=14)
    plt.axvline(x=0.5, color='red', linestyle='--', linewidth=2, label='50% coverage threshold')
    plt.axvline(x=val_df_viz['coverage'].mean(), color='blue', linestyle='--', 
                linewidth=2, label=f'Mean: {val_df_viz["coverage"].mean():.3f}')
    plt.legend()
    plt.grid(axis='y', alpha=0.3)
    save_fig(os.path.join(OUT_DIR, "plot_coverage_distribution.png"))
    log.info("Saved coverage distribution histogram")

if os.path.exists(val_csv):
    val_df_viz = pd.read_csv(val_csv)
    plt.figure(figsize=(8, 6))
    plt.scatter(val_df_viz['lstm_chain_probability'], 
                val_df_viz['markov_chain_probability'],
                alpha=0.3, s=10, color='purple')
    plt.xscale('log')
    plt.yscale('log')
    plt.xlabel('LSTM Chain Probability (log scale)', fontsize=12)
    plt.ylabel('Markov Chain Probability (log scale)', fontsize=12)
    plt.title('LSTM vs Markov Probability Comparison', fontsize=14)
    plt.grid(True, alpha=0.3)
    save_fig(os.path.join(OUT_DIR, "plot_lstm_vs_markov_probability.png"))
    log.info("Saved LSTM vs Markov probability scatter plot")

if not pre_long_df.empty:
    top_techniques = pre_long_df['name'].value_counts().head(10)
    plt.figure(figsize=(10, 6))
    top_techniques.plot(kind='barh', color='teal', edgecolor='black')
    plt.xlabel('Frequency (Number of Occurrences)', fontsize=12)
    plt.ylabel('Technique Name', fontsize=12)
    plt.title('Top-10 Most Frequent Techniques in Generated Chains', fontsize=14)
    plt.gca().invert_yaxis()
    plt.tight_layout()
    save_fig(os.path.join(OUT_DIR, "plot_top10_techniques.png"))
    log.info("Saved top-10 techniques bar chart")

log.info(f"All visualizations saved to: {OUT_DIR}")

# =========================================================
# README
# =========================================================
section("SUMMARY: counts & paths")
log.info(f"Pre-LSTM chains from MITRE campaigns: {len(pre_chains):,}")
log.info(f"JSON-derived chains (Markov training): {len(json_only):,}")
log.info(f"Post-LSTM chains scored: {len(post_df):,}")
log.info(f"Top Markov sequences generated: {len(mk_top_df):,}")
log.info(f"All outputs saved in: {OUT_DIR}")

readme = f"""# Attack-Chain Prediction & Risk Scoring

**Timestamp:** {STAMP}

## Order of Operations
1. Load ATT&CK v16 (techniques, sub-techniques via relationships, campaigns).
2. Pre-LSTM: generate tactic-ordered chains from campaigns; save wide/long catalogs.
3. LSTM: train next-step model; compute chain probabilities; per-step risk; save.
4. JSON ingest: read Unit42 playbooks and Attack Flow STIX (local) → sequences.
5. Markov: train 1st-order Markov on JSON-only sequences; save model and top paths.
6. Validation: compute Markov probabilities & coverage for POST-LSTM chains.
6b. Post-LSTM + Markov (stream-safe): expand & score sequences; write rows incrementally.
7. Risk: Likelihood × (1−Detection) per step; final risk = 10×(geo-mean like×OCTAVE/10), capped at 10.
   - Sorting: risk desc, then probability desc.
8. Dataset integration (optional): map labels → ATT&CK, filter post-Markov, rank & save.
8b. Dataset-anchored predictions: start from dataset attack types, predict most likely chains.

## Key Files
- pre-LSTM: pre_lstm_chains_(wide|long).csv, pre_lstm_chains.xlsx
- post-LSTM: post_lstm_chains_scored.(csv|xlsx), post_lstm_chains_scored_sorted.csv
- JSON sequences: external_sequences.csv
- Markov model: markov_model.json
- Markov-only top: markov_top_sequences.(csv|xlsx)
- Validation: validation_lstm_vs_markov.(csv|xlsx)
- Post-Markov (streamed): post_markov_expansions_stream.csv
- Post-Markov scored: markov_top_sequences_scored.(csv|xlsx)
- Dataset-filtered: dataset_label_filtered_chains.csv, dataset_label_top50_per_label.csv
- Dataset-anchored predictions: dataset_anchor_predicted_chains.(csv|xlsx), dataset_anchor_nextstep_probs.csv, dataset_anchor_top100_per_anchor.csv
- Plots: plot_lstm_loss.png, plot_lstm_acc.png, plot_risk_vs_likelihood_post_markov.png
"""
with open(os.path.join(OUT_DIR, "README.md"), "w", encoding="utf-8") as f:
    f.write(readme)

# =========================================================
# NEW SECTION 9: Three-Scenario LSTM Training
# =========================================================
if RUN_THREE_SCENARIOS and campaign_severity:
    section("STEP 9) THREE-SCENARIO LSTM TRAINING (100% TRUE training, then 50/50 & 80/20 with error analysis)")
    log.info("Running three training scenarios:")
    log.info("  - 100% trained (100% of data, NO validation split, NO error analysis)")
    log.info("  - 50/50 split with error analysis vs NCISS scores")
    log.info("  - 80/20 split with error analysis vs NCISS scores")
    
    def train_lstm_scenario(scenario_name, train_split=1.0):
        """Train LSTM with specified train/test split"""
        log.info(f"\n{'='*60}")
        log.info(f"Training LSTM: {scenario_name} scenario (split={train_split})")
        log.info(f"{'='*60}")
        
        perm_sc = np.random.permutation(len(X_list))
        
        # TRUE 100% TRAINING - NO VALIDATION SPLIT
        if train_split == 1.0:
            log.info("  Using 100% of data for training (NO validation split)")
            train_idx_sc = perm_sc  # Use ALL data
            test_idx_sc = []  # No test data
        else:
            cut_sc = int(train_split * len(perm_sc))
            train_idx_sc, test_idx_sc = perm_sc[:cut_sc], perm_sc[cut_sc:]
        
        train_ds_sc = ChainDataset([X_list[i] for i in train_idx_sc], [Y_list[i] for i in train_idx_sc])
        
        # Only create test dataset if we have test indices
        if len(test_idx_sc) > 0:
            test_ds_sc = ChainDataset([X_list[i] for i in test_idx_sc], [Y_list[i] for i in test_idx_sc])
            test_loader_sc = DataLoader(test_ds_sc, batch_size=BATCH_SIZE, shuffle=False, collate_fn=collate)
        else:
            test_loader_sc = None
        
        train_loader_sc = DataLoader(train_ds_sc, batch_size=BATCH_SIZE, shuffle=True, collate_fn=collate)
        
        model_sc = NextStepLSTM(vocab_size=len(vocab)).to(device)
        opt_sc = torch.optim.AdamW(model_sc.parameters(), lr=LR)
        loss_fn_sc = nn.CrossEntropyLoss()
        
        train_losses_sc, test_losses_sc, train_accs_sc, test_accs_sc = [], [], [], []
        
        for epoch in range(1, EPOCHS+1):
            # Train
            model_sc.train()
            total, correct, loss_sum = 0, 0, 0.0
            for xb, yb, lb in train_loader_sc:
                xb, yb, lb = xb.to(device), yb.to(device), lb.to(device)
                logits = model_sc(xb, lb)
                loss = loss_fn_sc(logits, yb)
                opt_sc.zero_grad(); loss.backward(); opt_sc.step()
                with torch.no_grad():
                    preds = logits.argmax(dim=-1)
                    correct += (preds == yb).sum().item()
                    total += yb.numel()
                    loss_sum += loss.item() * yb.numel()
            tr_loss = loss_sum/total if total else 0.0
            tr_acc = correct/total if total else 0.0
            train_losses_sc.append(tr_loss); train_accs_sc.append(tr_acc)
            
            # Test (only if test_loader exists)
            if test_loader_sc is not None:
                model_sc.eval()
                total, correct, loss_sum = 0, 0, 0.0
                with torch.no_grad():
                    for xb, yb, lb in test_loader_sc:
                        xb, yb, lb = xb.to(device), yb.to(device), lb.to(device)
                        logits = model_sc(xb, lb)
                        loss = loss_fn_sc(logits, yb)
                        preds = logits.argmax(dim=-1)
                        correct += (preds == yb).sum().item()
                        total += yb.numel()
                        loss_sum += loss.item() * yb.numel()
                te_loss = loss_sum/total if total else 0.0
                te_acc = correct/total if total else 0.0
                test_losses_sc.append(te_loss); test_accs_sc.append(te_acc)
            else:
                # For 100% scenario with no test data
                test_losses_sc.append(None); test_accs_sc.append(None)
                te_loss, te_acc = None, None
            
            if epoch % 10 == 0:
                if te_loss is not None:
                    log.info(f"  Epoch {epoch:02d}/{EPOCHS} | train {tr_loss:.4f}/{tr_acc:.3f} | test {te_loss:.4f}/{te_acc:.3f}")
                else:
                    log.info(f"  Epoch {epoch:02d}/{EPOCHS} | train {tr_loss:.4f}/{tr_acc:.3f} | NO TEST DATA")
        
        return {
            'model': model_sc,
            'train_losses': train_losses_sc,
            'test_losses': test_losses_sc,
            'train_accs': train_accs_sc,
            'test_accs': test_accs_sc
        }
    
    def score_chain_with_model(seq_names, model_sc):
        """Score chain using specific model"""
        model_sc.eval()
        with torch.no_grad():
            modeled_next = []
            for i in range(1, len(seq_names)):
                prefix = seq_names[:i]
                target = seq_names[i]
                prefix_ids = [stoi[s] for s in prefix if s in stoi]
                target_id = stoi.get(target, None)
                if len(prefix_ids) == 0 or target_id is None:
                    modeled_next.append(None); continue
                t = torch.tensor(prefix_ids, dtype=torch.long).unsqueeze(0).to(device)
                l = torch.tensor([len(prefix_ids)], dtype=torch.long).to(device)
                logits = model_sc(t, l).squeeze(0)
                probs = torch.softmax(logits, dim=-1).cpu().numpy()
                modeled_next.append(float(probs[target_id]))
        
        per_step_likes = []
        for i, name in enumerate(seq_names):
            modeled_prob = modeled_next[i-1] if i > 0 and i-1 < len(modeled_next) else None
            like = step_likelihood(name, modeled_prob)
            per_step_likes.append(like)
        
        chain_like = max(MARKOV_MIN_PROB, min(1.0, geometric_mean_prob([max(p,MARKOV_MIN_PROB) for p in per_step_likes if p is not None and p > 0.0])))
        final_risk = 10.0 * chain_like * (OCTAVE_IMPACT_0_10_DEFAULT / 10.0)
        final_risk = min(10.0, final_risk)
        
        return final_risk, chain_like
    
    def calculate_error_rates(predictions_df, severity_dict):
        """Calculate error metrics"""
        results = []
        for _, row in predictions_df.iterrows():
            camp_id = row['campaign_id']
            if camp_id in severity_dict:
                predicted = row['final_risk_score_0_10']
                actual = severity_dict[camp_id]
                abs_err = abs(predicted - actual)
                rel_err = (abs_err / actual * 100) if actual > 0 else 0
                results.append({
                    'campaign_id': camp_id,
                    'campaign_name': row['campaign'],
                    'predicted_risk': predicted,
                    'actual_severity': actual,
                    'absolute_error': abs_err,
                    'relative_error_pct': rel_err
                })
        
        if not results:
            return pd.DataFrame(), {}
        
        error_df = pd.DataFrame(results)
        stats = {
            'mean_absolute_error': error_df['absolute_error'].mean(),
            'std_absolute_error': error_df['absolute_error'].std(),
            'mean_relative_error_pct': error_df['relative_error_pct'].mean(),
            'median_absolute_error': error_df['absolute_error'].median(),
            'max_absolute_error': error_df['absolute_error'].max(),
            'min_absolute_error': error_df['absolute_error'].min(),
            'total_predictions': len(error_df)
        }
        return error_df, stats
    
    scenarios = [
        ("100%", 1.0, False),   # TRUE 100% training, NO error analysis
        ("50-50", 0.5, True),   # 50/50 with error analysis
        ("80-20", 0.8, True)    # 80/20 with error analysis
    ]
    all_scenario_results = {}
    
    for scenario_name, train_split, do_error_analysis in scenarios:
        model_info = train_lstm_scenario(scenario_name, train_split)
        
        pred_rows = []
        for cid, (camp_id, camp_name, chain) in enumerate(zip(campaign_ids_index, campaign_index, all_chains), start=1):
            risk, likelihood = score_chain_with_model(chain, model_info['model'])
            pred_rows.append({
                'chain_id': cid,
                'campaign_id': camp_id,
                'campaign': camp_name,
                'chain_length': len(chain),
                'final_risk_score_0_10': risk,
                'chain_geomean_likelihood': likelihood
            })
        
        pred_df = pd.DataFrame(pred_rows)
        
        scenario_dir = os.path.join(OUT_DIR, f"scenario_{scenario_name.replace('/', '-')}")
        os.makedirs(scenario_dir, exist_ok=True)
        
        pred_df.to_csv(os.path.join(scenario_dir, "predictions.csv"), index=False)
        
        error_df = pd.DataFrame()
        error_stats = {}
        if do_error_analysis:
            error_df, error_stats = calculate_error_rates(pred_df, campaign_severity)
            if not error_df.empty:
                error_df.to_csv(os.path.join(scenario_dir, "error_analysis.csv"), index=False)
                with open(os.path.join(scenario_dir, "error_statistics.txt"), "w") as f:
                    f.write(f"Error Analysis for {scenario_name} Training Scenario\n")
                    f.write("="*60 + "\n\n")
                    for key, value in error_stats.items():
                        f.write(f"{key}: {value:.4f}\n")
        
        # Plots - handle None values for 100% scenario
        plt.figure(figsize=(10, 5))
        plt.plot(range(1, EPOCHS+1), model_info['train_losses'], marker="o", label="train loss")
        if model_info['test_losses'][0] is not None:
            plt.plot(range(1, EPOCHS+1), model_info['test_losses'], marker="o", label="test loss")
        plt.xlabel("Epoch"); plt.ylabel("Loss"); plt.title(f"LSTM Loss - {scenario_name}"); plt.legend()
        save_fig(os.path.join(scenario_dir, "plot_lstm_loss.png"))
        
        plt.figure(figsize=(10, 5))
        plt.plot(range(1, EPOCHS+1), model_info['train_accs'], marker="o", label="train acc")
        if model_info['test_accs'][0] is not None:
            plt.plot(range(1, EPOCHS+1), model_info['test_accs'], marker="o", label="test acc")
        plt.xlabel("Epoch"); plt.ylabel("Accuracy"); plt.title(f"LSTM Accuracy - {scenario_name}"); plt.legend()
        save_fig(os.path.join(scenario_dir, "plot_lstm_acc.png"))
        
        if do_error_analysis and not error_df.empty:
            plt.figure(figsize=(10, 6))
            plt.hist(error_df['absolute_error'], bins=30, edgecolor='black', alpha=0.7, color='coral')
            plt.xlabel('Absolute Error'); plt.ylabel('Frequency')
            plt.title(f'Error Distribution - {scenario_name}')
            plt.axvline(x=error_stats['mean_absolute_error'], color='red', linestyle='--', 
                       label=f'Mean: {error_stats["mean_absolute_error"]:.2f}')
            plt.legend()
            save_fig(os.path.join(scenario_dir, "plot_error_distribution.png"))
            
            plt.figure(figsize=(10, 6))
            plt.scatter(error_df['actual_severity'], error_df['predicted_risk'], alpha=0.5, s=50)
            plt.plot([0, 10], [0, 10], 'r--', linewidth=2, label='Perfect prediction')
            plt.xlabel('Actual Severity (NCISS)'); plt.ylabel('Predicted Risk')
            plt.title(f'Predicted vs Actual - {scenario_name}'); plt.legend()
            save_fig(os.path.join(scenario_dir, "plot_predicted_vs_actual.png"))
        
        all_scenario_results[scenario_name] = {
            'predictions': pred_df,
            'errors': error_df,
            'statistics': error_stats
        }
        
        log.info(f"\n{'='*60}")
        log.info(f"RESULTS SUMMARY FOR {scenario_name} SCENARIO")
        log.info(f"{'='*60}")
        log.info(f"Total predictions: {len(pred_df):,}")
        if do_error_analysis and error_stats:
            log.info(f"Mean Absolute Error: {error_stats['mean_absolute_error']:.4f}")
            log.info(f"Std Absolute Error: {error_stats['std_absolute_error']:.4f}")
            log.info(f"Mean Relative Error: {error_stats['mean_relative_error_pct']:.2f}%")
            log.info(f"Median Absolute Error: {error_stats['median_absolute_error']:.4f}")
        else:
            log.info("Error analysis: SKIPPED (baseline scenario with 100% training)")
        log.info(f"Results saved to: {scenario_dir}")
    
    section("STEP 10) Cross-Scenario Comparison (50/50 vs 80/20)")
    comparison_rows = []
    for scenario_name in ["50-50", "80-20"]:
        if scenario_name in all_scenario_results and all_scenario_results[scenario_name]['statistics']:
            stats = all_scenario_results[scenario_name]['statistics']
            comparison_rows.append({
                'scenario': scenario_name,
                'mean_absolute_error': stats['mean_absolute_error'],
                'std_absolute_error': stats['std_absolute_error'],
                'mean_relative_error_pct': stats['mean_relative_error_pct'],
                'median_absolute_error': stats['median_absolute_error']
            })
    
    if comparison_rows:
        comparison_df = pd.DataFrame(comparison_rows)
        comparison_csv = os.path.join(OUT_DIR, "scenario_comparison_5050_vs_8020.csv")
        comparison_df.to_csv(comparison_csv, index=False)
        
        log.info("\nSCENARIO COMPARISON TABLE (50/50 vs 80/20):")
        log.info("="*100)
        log.info(f"{'Scenario':<15} {'MAE':<12} {'Std':<12} {'Rel Err %':<12} {'Median':<12}")
        log.info("-"*100)
        for _, row in comparison_df.iterrows():
            log.info(f"{row['scenario']:<15} {row['mean_absolute_error']:<12.4f} "
                    f"{row['std_absolute_error']:<12.4f} {row['mean_relative_error_pct']:<12.2f} "
                    f"{row['median_absolute_error']:<12.4f}")
        log.info("="*100)
        
        plt.figure(figsize=(12, 6))
        x = np.arange(len(comparison_df))
        width = 0.25
        plt.bar(x - width, comparison_df['mean_absolute_error'], width, label='MAE', alpha=0.8)
        plt.bar(x, comparison_df['median_absolute_error'], width, label='Median', alpha=0.8)
        plt.bar(x + width, comparison_df['std_absolute_error'], width, label='Std', alpha=0.8)
        plt.xlabel('Scenario'); plt.ylabel('Error Magnitude')
        plt.title('Error Comparison: 50/50 vs 80/20 Training Scenarios')
        plt.xticks(x, comparison_df['scenario'])
        plt.legend()
        save_fig(os.path.join(OUT_DIR, "plot_scenario_comparison_5050_vs_8020.png"))
        
        log.info(f"\nComparison results saved to: {comparison_csv}")
    
    log.info("\n" + "="*60)
    log.info("THREE-SCENARIO TRAINING SUMMARY")
    log.info("="*60)
    log.info("✓ 100% baseline scenario completed (TRUE 100% training, no validation, no error analysis)")
    log.info("✓ 50/50 split scenario completed with error analysis")
    log.info("✓ 80/20 split scenario completed with error analysis")
    log.info("✓ Cross-scenario comparison generated (50/50 vs 80/20)")
    
    scenarios_readme = f"""# Three-Scenario LSTM Training Summary

**Timestamp:** {STAMP}

## Scenarios Overview

### 1. 100% Baseline Training
- **Purpose**: Establish baseline performance using ALL available data
- **Train/Test Split**: 100% training / 0% validation (TRUE 100% training)
- **Error Analysis**: NOT PERFORMED (baseline reference only)
- **Output Directory**: scenario_100%
- **Note**: This scenario uses the entire dataset for training with NO held-out validation data

### 2. 50/50 Split Training
- **Purpose**: Test performance with balanced train/test split
- **Train/Test Split**: 50% training / 50% testing
- **Error Analysis**: PERFORMED vs NCISS severity scores
- **Output Directory**: scenario_50-50

### 3. 80/20 Split Training
- **Purpose**: Test performance with common ML train/test split
- **Train/Test Split**: 80% training / 20% testing
- **Error Analysis**: PERFORMED vs NCISS severity scores
- **Output Directory**: scenario_80-20

## Key Differences

- **100% Scenario**: Uses 100% of data for training (no validation split)
  - NO comparison to NCISS severity scores
  - NO error analysis or metrics
  - Provides predictions and risk scores only
  - Serves as maximum-data baseline
  - Training curves show only train loss/accuracy (no test metrics)

- **50/50 & 80/20 Scenarios**: Split data for training/testing
  - Full error analysis vs NCISS severity scores
  - Includes error metrics (MAE, relative error, median, std, etc.)
  - Generates error distribution plots
  - Predicted vs Actual scatter plots
  - Training curves show both train and test metrics

## Files Per Scenario

**100% Scenario directory contains:**
- `predictions.csv` - All chain predictions with risk scores
- `plot_lstm_loss.png` - Training loss curve only (no test curve)
- `plot_lstm_acc.png` - Training accuracy curve only (no test curve)

**50/50 and 80/20 Scenario directories contain:**
- `predictions.csv` - All chain predictions with risk scores
- `error_analysis.csv` - Detailed error metrics per campaign
- `error_statistics.txt` - Summary statistics (MAE, std, median, etc.)
- `plot_lstm_loss.png` - Training and test loss curves
- `plot_lstm_acc.png` - Training and test accuracy curves
- `plot_error_distribution.png` - Error distribution histogram
- `plot_predicted_vs_actual.png` - Scatter plot of predictions vs ground truth

## Cross-Scenario Comparison

- `scenario_comparison_5050_vs_8020.csv` - Statistical comparison of 50/50 vs 80/20
- `plot_scenario_comparison_5050_vs_8020.png` - Visual comparison bar chart

**Note**: The 100% scenario is excluded from error analysis and cross-scenario comparison 
because it serves as a pure baseline using all available training data without validation.

## Training Approach

- **100%**: Trains on entire dataset (no validation split during training)
- **50/50**: Trains on 50% of data, validates/tests on remaining 50%
- **80/20**: Trains on 80% of data, validates/tests on remaining 20%

All scenarios use the same LSTM architecture, hyperparameters, and training procedure.
Only the data split differs between scenarios.
"""
    
    with open(os.path.join(OUT_DIR, "THREE_SCENARIO_README.md"), "w", encoding="utf-8") as f:
        f.write(scenarios_readme)
    
    log.info(f"Three-scenario summary README saved")

elif not campaign_severity:
    log.warning("Three-scenario training skipped: No severity scores loaded")
elif not RUN_THREE_SCENARIOS:
    log.info("Three-scenario training skipped: RUN_THREE_SCENARIOS=0")

# Final summary
section("PIPELINE COMPLETE - ALL STEPS FINISHED")
log.info(f"All outputs saved in: {OUT_DIR}")
log.info("Original pipeline (Steps 1-8b): ✓ Complete")
if RUN_THREE_SCENARIOS and campaign_severity:
    log.info("Three-scenario analysis (Steps 9-10): ✓ Complete")
    log.info("  - 100% baseline (TRUE 100% training, no error analysis): ✓")
    log.info("  - 50/50 split (with error analysis): ✓")
    log.info("  - 80/20 split (with error analysis): ✓")
log.info("\nCheck the output directory for all results!")

# =========================================================
# TOP 10 CHAINS BY RISK SCORE WITH SEVERITY ANALYSIS
# =========================================================
section("TOP 10 CHAINS BY RISK SCORE WITH SEVERITY ANALYSIS")

if not post_df.empty:
    # Create a comprehensive top 10 analysis
    top10_chains = post_df.sort_values('final_risk_score_0_10', ascending=False).head(10).copy()
    
    # Add severity scores where available
    top10_chains['nciss_severity'] = top10_chains['campaign_id'].map(campaign_severity)
    top10_chains['has_severity'] = top10_chains['nciss_severity'].notna()
    
    # Calculate delta between predicted risk and actual severity (where available)
    top10_chains['risk_severity_delta'] = top10_chains.apply(
        lambda row: row['final_risk_score_0_10'] - row['nciss_severity'] 
        if pd.notna(row['nciss_severity']) else None, axis=1
    )
    
    # Create detailed output
    top10_detailed = top10_chains[[
        'chain_id', 'campaign_id', 'campaign', 'chain_length',
        'final_risk_score_0_10', 'nciss_severity', 'risk_severity_delta',
        'chain_geomean_likelihood', 'lstm_chain_probability', 'chain'
    ]].copy()
    
    # Save to CSV and Excel
    top10_csv = os.path.join(OUT_DIR, "top10_chains_by_risk_with_severity.csv")
    top10_xlsx = os.path.join(OUT_DIR, "top10_chains_by_risk_with_severity.xlsx")
    
    top10_detailed.to_csv(top10_csv, index=False)
    with pd.ExcelWriter(top10_xlsx, engine="xlsxwriter") as xlw:
        top10_detailed.to_excel(xlw, index=False, sheet_name="Top10Chains")
    
    log.info(f"Saved Top-10 chains with severity analysis:\n  {top10_csv}\n  {top10_xlsx}")
    
    # Print formatted table to terminal
    log.info("\n" + "="*120)
    log.info("TOP 10 CHAINS BY PREDICTED RISK SCORE")
    log.info("="*120)
    log.info(f"{'Rank':<6} {'Chain ID':<10} {'Risk':<8} {'Severity':<10} {'Delta':<8} {'Likelihood':<12} {'Campaign':<30}")
    log.info("-"*120)
    
    for rank, (_, row) in enumerate(top10_detailed.iterrows(), start=1):
        severity_str = f"{row['nciss_severity']:.2f}" if pd.notna(row['nciss_severity']) else "N/A"
        delta_str = f"{row['risk_severity_delta']:+.2f}" if pd.notna(row['risk_severity_delta']) else "N/A"
        campaign_name = row['campaign'][:28] + ".." if len(row['campaign']) > 30 else row['campaign']
        
        log.info(f"{rank:<6} {int(row['chain_id']):<10} {row['final_risk_score_0_10']:<8.2f} "
                f"{severity_str:<10} {delta_str:<8} {row['chain_geomean_likelihood']:<12.4f} {campaign_name:<30}")
    
    log.info("="*120)
    
    # Additional statistics
    chains_with_severity = top10_chains[top10_chains['has_severity']]
    if len(chains_with_severity) > 0:
        log.info(f"\nSTATISTICS FOR TOP-10 CHAINS WITH SEVERITY SCORES ({len(chains_with_severity)}/{len(top10_chains)}):")
        log.info(f"  Mean Risk Score: {chains_with_severity['final_risk_score_0_10'].mean():.2f}")
        log.info(f"  Mean Severity Score: {chains_with_severity['nciss_severity'].mean():.2f}")
        log.info(f"  Mean Absolute Delta: {abs(chains_with_severity['risk_severity_delta']).mean():.2f}")
        log.info(f"  Correlation (Risk vs Severity): {chains_with_severity[['final_risk_score_0_10', 'nciss_severity']].corr().iloc[0,1]:.3f}")
    
    # Visualization: Top 10 chains comparison
    plt.figure(figsize=(12, 8))
    
    x_pos = np.arange(len(top10_detailed))
    
    plt.barh(x_pos, top10_detailed['final_risk_score_0_10'], 
             alpha=0.7, color='crimson', label='Predicted Risk Score')
    
    # Overlay severity scores where available
    has_severity_mask = top10_detailed['nciss_severity'].notna()
    if has_severity_mask.any():
        plt.barh(x_pos[has_severity_mask], 
                top10_detailed.loc[has_severity_mask, 'nciss_severity'],
                alpha=0.5, color='blue', label='NCISS Severity Score')
    
    plt.yticks(x_pos, [f"#{i+1} (ID:{int(row['chain_id'])})" 
                       for i, (_, row) in enumerate(top10_detailed.iterrows())])
    plt.xlabel('Score (0-10 scale)', fontsize=12)
    plt.ylabel('Chain Rank', fontsize=12)
    plt.title('Top-10 Chains: Predicted Risk vs Actual Severity', fontsize=14)
    plt.legend()
    plt.xlim(0, 10)
    plt.grid(axis='x', alpha=0.3)
    
    save_fig(os.path.join(OUT_DIR, "plot_top10_risk_vs_severity.png"))
    log.info("Saved Top-10 visualization: plot_top10_risk_vs_severity.png")
    
    # Detailed chain view
    log.info("\n" + "="*120)
    log.info("DETAILED VIEW OF TOP-3 CHAINS")
    log.info("="*120)
    
    for rank, (_, row) in enumerate(top10_detailed.head(3).iterrows(), start=1):
        log.info(f"\n--- RANK #{rank} ---")
        log.info(f"Chain ID: {int(row['chain_id'])}")
        log.info(f"Campaign: {row['campaign']} (ID: {row['campaign_id']})")
        log.info(f"Chain Length: {int(row['chain_length'])} techniques")
        log.info(f"Predicted Risk Score: {row['final_risk_score_0_10']:.2f}")
        if pd.notna(row['nciss_severity']):
            log.info(f"NCISS Severity Score: {row['nciss_severity']:.2f}")
            log.info(f"Prediction Delta: {row['risk_severity_delta']:+.2f}")
        else:
            log.info(f"NCISS Severity Score: Not Available")
        log.info(f"Likelihood (geometric mean): {row['chain_geomean_likelihood']:.4f}")
        log.info(f"LSTM Chain Probability: {row['lstm_chain_probability']:.3e}")
        log.info(f"Attack Chain:\n  {row['chain']}")
    
    log.info("\n" + "="*120)

else:
    log.warning("No POST-LSTM chains available for Top-10 analysis")

# =========================================================
# ADDITIONAL: Top 10 by Severity (if available)
# =========================================================
if campaign_severity and not post_df.empty:
    section("TOP 10 CHAINS BY ACTUAL SEVERITY SCORE (NCISS)")
    
    # Filter chains that have severity scores
    chains_with_severity = post_df[post_df['campaign_id'].isin(campaign_severity.keys())].copy()
    chains_with_severity['nciss_severity'] = chains_with_severity['campaign_id'].map(campaign_severity)
    
    if not chains_with_severity.empty:
        top10_by_severity = chains_with_severity.sort_values('nciss_severity', ascending=False).head(10)
        
        top10_severity_detailed = top10_by_severity[[
            'chain_id', 'campaign_id', 'campaign', 'chain_length',
            'nciss_severity', 'final_risk_score_0_10', 
            'chain_geomean_likelihood', 'chain'
        ]].copy()
        
        top10_severity_detailed['risk_severity_delta'] = (
            top10_severity_detailed['final_risk_score_0_10'] - 
            top10_severity_detailed['nciss_severity']
        )
        
        top10_severity_csv = os.path.join(OUT_DIR, "top10_chains_by_actual_severity.csv")
        top10_severity_detailed.to_csv(top10_severity_csv, index=False)
        
        log.info(f"Saved Top-10 chains by actual severity: {top10_severity_csv}")
        
        log.info("\n" + "="*120)
        log.info("TOP 10 CHAINS BY ACTUAL SEVERITY SCORE (NCISS)")
        log.info("="*120)
        log.info(f"{'Rank':<6} {'Chain ID':<10} {'Severity':<10} {'Risk':<8} {'Delta':<8} {'Campaign':<40}")
        log.info("-"*120)
        
        for rank, (_, row) in enumerate(top10_severity_detailed.iterrows(), start=1):
            delta_str = f"{row['risk_severity_delta']:+.2f}"
            campaign_name = row['campaign'][:38] + ".." if len(row['campaign']) > 40 else row['campaign']
            
            log.info(f"{rank:<6} {int(row['chain_id']):<10} {row['nciss_severity']:<10.2f} "
                    f"{row['final_risk_score_0_10']:<8.2f} {delta_str:<8} {campaign_name:<40}")
        
        log.info("="*120)
        
        # Statistics
        log.info(f"\nSTATISTICS FOR TOP-10 BY SEVERITY:")
        log.info(f"  Mean Severity Score: {top10_severity_detailed['nciss_severity'].mean():.2f}")
        log.info(f"  Mean Risk Score: {top10_severity_detailed['final_risk_score_0_10'].mean():.2f}")
        log.info(f"  Mean Prediction Delta: {top10_severity_detailed['risk_severity_delta'].mean():+.2f}")
        log.info(f"  Correlation: {top10_severity_detailed[['nciss_severity', 'final_risk_score_0_10']].corr().iloc[0,1]:.3f}")
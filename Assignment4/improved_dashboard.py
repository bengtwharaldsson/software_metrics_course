import random
from pathlib import Path
from datetime import datetime
import pandas as pd
import streamlit as st
import altair as alt


st.set_page_config(page_title="Project dashboard", layout="wide")

# -----------------------------
# Config
# -----------------------------
XLSX_PATH = "Total_metric_data.xlsx"         # change if needed
GCC_SHEET = "data_gcc_180"
IQ_LOG_PATH = "information_quality.log"      # change if needed

CLOSED_STATUSES = {"RESOLVED", "CLOSED"}     # define what "closed" means

# -----------------------------
# CSS
# -----------------------------
st.markdown("""
<style>
.tile {
  border-radius: 12px;
  padding: 14px 16px;
  background: #1f1f1f;
  border: 1px solid rgba(255,255,255,0.10);
  color: white;
}
.section-title {
  border-radius: 12px;
  padding: 14px 16px;
  background: #444444;
  color: white;
  font-weight: 800;
}
.small { color: rgba(255,255,255,0.75); font-size: 0.9rem; }

.status-good    { background: #1f6f3a !important; }  /* green */
.status-warning { background: #a67c00 !important; }  /* yellow */
.status-danger  { background: #8b1e1e !important; }  /* red */

.badge {
  font-size: 0.78rem;
  padding: 3px 8px;
  border-radius: 999px;
  border: 1px solid rgba(255,255,255,0.18);
  margin-left: 6px;
  display: inline-block;
  color: white;
}
</style>
""", unsafe_allow_html=True)

# -----------------------------
# IQ parsing (latest run only)
# -----------------------------
def parse_iq_log_latest_run(log_path: str) -> dict:
    """
    Parses information_quality.log and returns IQ status for the latest run.
    Run is defined as lines after the last 'Configuration started'.
    """
    p = Path(log_path)
    if not p.exists():
        return {
            "overall": "status-danger",
            "last_run_start": None,
            "last_run_end": None,
            "dimensions": {
                "Configuration": ("status-danger", "Log file not found"),
                "Collection": ("status-danger", "Log file not found"),
                "Persistence": ("status-danger", "Log file not found"),
                "Validation": ("status-danger", "Log file not found"),
                "Computation": ("status-danger", "Log file not found"),
            },
            "notes": ["information_quality.log not found at: " + str(p.resolve())],
        }

    # Parse log lines: "timestamp;module;LEVEL;message"
    rows = []
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        parts = line.split(";", 3)
        if len(parts) != 4:
            continue
        ts_s, module, level, msg = parts
        try:
            ts = datetime.strptime(ts_s.strip(), "%Y-%m-%d %H:%M:%S,%f")
        except Exception:
            continue
        rows.append((ts, module.strip(), level.strip().upper(), msg.strip()))

    if not rows:
        return {
            "overall": "status-danger",
            "last_run_start": None,
            "last_run_end": None,
            "dimensions": {
                "Configuration": ("status-danger", "Log unreadable/empty"),
                "Collection": ("status-danger", "Log unreadable/empty"),
                "Persistence": ("status-danger", "Log unreadable/empty"),
                "Validation": ("status-danger", "Log unreadable/empty"),
                "Computation": ("status-danger", "Log unreadable/empty"),
            },
            "notes": ["No parseable log rows found."],
        }

    # Find last run start marker
    start_idx = None
    for i in range(len(rows) - 1, -1, -1):
        if "Configuration started" in rows[i][3]:
            start_idx = i
            break

    if start_idx is None:
        # No run delimiter found; treat whole log as one run
        run = rows
        last_run_start = rows[0][0]
    else:
        run = rows[start_idx:]
        last_run_start = rows[start_idx][0]

    last_run_end = run[-1][0] if run else None

    # Helper counts
    levels = [lvl for _, _, lvl, _ in run]
    has_error = "ERROR" in levels
    has_warning = "WARNING" in levels

    # Dimension evidence rules (based on your log snippet)
    messages = [m for _, _, _, m in run]
    modules = [mod for _, mod, _, _ in run]

    def dim_status(name: str, ok_if_any: list[str], warn_if_any: list[str] = None, required: bool = True):
        warn_if_any = warn_if_any or []
        ok_hit = any(any(token in m for token in ok_if_any) for m in messages)
        warn_hit = any(any(token in m for token in warn_if_any) for m in messages)

        if any(lvl == "ERROR" for _, _, lvl, _ in run):
            # If there is an error in the run, dims that didn't hit OK become red, OK ones become yellow
            if ok_hit:
                return ("status-warning", "OK evidence found, but run contains ERROR")
            return ("status-danger", "No OK evidence found and run contains ERROR")

        if ok_hit:
            if warn_hit or has_warning:
                return ("status-warning", "OK evidence found, but warnings present")
            return ("status-good", "OK")
        else:
            if required:
                # Missing a required stage => degraded
                return ("status-warning", "Missing expected success evidence in latest run")
            return ("status-warning", "No evidence")

    dimensions = {
        "Configuration": dim_status(
            "Configuration",
            ok_if_any=[
                "Configuration loaded successfully",
                "All modules imported successfully",
                "Configuration started",
            ],
            required=True,
        ),
        "Collection": dim_status(
            "Collection",
            ok_if_any=[
                "Raw data download complete",
                ' "GET ',  # request line in urllib3 debug
                "Starting new HTTPS connection",
            ],
            required=True,
        ),
        "Persistence": dim_status(
            "Persistence",
            ok_if_any=[
                "Raw data saved to file successfully",
            ],
            required=False,  # depending on pipeline, saving may be optional
        ),
        "Validation": dim_status(
            "Validation",
            ok_if_any=[
                "Total resolved issues OK.",
                "Total issues OK.",
                "Total resolved non-bugs OK.",
            ],
            required=False,
        ),
        "Computation": dim_status(
            "Computation",
            ok_if_any=[
                "Resolution time calculation completed successfully.",
                "Resolved issues found for resolution time calculation.",
            ],
            required=False,
        ),
    }

    # Overall logic
    dim_classes = [cls for cls, _ in dimensions.values()]
    if "status-danger" in dim_classes:
        overall = "status-danger"
    elif "status-warning" in dim_classes:
        overall = "status-warning"
    else:
        overall = "status-good"

    notes = []
    if has_error:
        notes.append("ERROR detected in latest run.")
    if has_warning:
        notes.append("WARNING detected in latest run.")
    if start_idx is None:
        notes.append("No 'Configuration started' marker found; used whole file as one run.")

    return {
        "overall": overall,
        "last_run_start": last_run_start,
        "last_run_end": last_run_end,
        "dimensions": dimensions,
        "notes": notes,
    }

# -----------------------------
# Defects helpers
# -----------------------------
def defects_status(defects: int, warning_limit: int) -> str:
    if defects == 0:
        return "status-good"
    return "status-warning" if defects <= warning_limit else "status-danger"

def percent(executed: int, total: int) -> int:
    return int(round(100 * executed / total, 0)) if total else 0

# -----------------------------
# Load data
# -----------------------------
st.title("Project dashboard")

# IQ widget (global)
iq = parse_iq_log_latest_run(IQ_LOG_PATH)
start_s = iq["last_run_start"].strftime("%Y-%m-%d %H:%M:%S") if iq["last_run_start"] else "Unknown"
end_s = iq["last_run_end"].strftime("%Y-%m-%d %H:%M:%S") if iq["last_run_end"] else "Unknown"

# Render IQ global widget with per-dimension badges
badges_html = []
for dim, (cls, expl) in iq["dimensions"].items():
    badges_html.append(f'<span class="badge {cls}" title="{expl}">{dim}</span>')
badges_joined = "".join(badges_html)

overall_text = "OK" if iq["overall"] == "status-good" else ("Degraded" if iq["overall"] == "status-warning" else "Broken")

notes_line = (" • " + " ".join(iq["notes"])) if iq["notes"] else ""

st.markdown(
    f"""
    <div class="tile {iq['overall']}">
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <div style="font-weight:900; font-size:1.1rem;">Measurement system IQ: {overall_text}</div>
        <div>{badges_joined}</div>
      </div>
      <div class="small" style="margin-top:8px;">
        Latest run: {start_s} → {end_s}{notes_line}
      </div>
    </div>
    """,
    unsafe_allow_html=True
)

st.divider()

# Read GCC bug tickets
try:
    bugs = pd.read_excel(XLSX_PATH, sheet_name=GCC_SHEET)
except Exception as e:
    st.error(f"Could not read {XLSX_PATH} / sheet '{GCC_SHEET}': {e}")
    st.stop()

#st.write("Reached after IQ parsing")

#st.write("Excel file path:", XLSX_PATH)
#st.write("Log file path:", IQ_LOG_PATH)

#st.write("Bugs df shape:", bugs.shape)
#st.write("Bugs columns:", list(bugs.columns))
#st.write("First rows:", bugs.head(3))

# Normalize columns (in your sheet it's bug_severity; sometimes also severity)
# We'll rely on bug_status/component/bug_id being present.
required_cols = {"bug_id", "component", "bug_status", "resolution", "opendate", "changeddate"}
missing = required_cols - set(bugs.columns)
if missing:
    st.error(f"Missing expected columns in '{GCC_SHEET}': {sorted(missing)}")
    st.stop()

# Define open bugs
open_bugs = bugs[~bugs["bug_status"].astype(str).str.upper().isin(CLOSED_STATUSES)].copy()

# Pick two "subsystems" as the top 2 components by open bug count
top_components = (
    open_bugs["component"].astype(str).value_counts().head(2).index.tolist()
)
if len(top_components) < 2:
    # fallback
    top_components = (bugs["component"].astype(str).value_counts().head(2).index.tolist() + ["(none)"])[:2]

comp_a, comp_b = top_components[0], top_components[1]

defects_a = int((open_bugs["component"].astype(str) == comp_a).sum())
defects_b = int((open_bugs["component"].astype(str) == comp_b).sum())

# Progress meters now represent resolution progress (not random)
total_issues = len(bugs)
resolved_issues = int(bugs["bug_status"].astype(str).str.upper().isin(CLOSED_STATUSES).sum())
open_issues = total_issues - resolved_issues

resolved_pct = percent(resolved_issues, total_issues)

# Two meters: overall resolution + triage proxy (assigned_to != unassigned)
triaged_issues = int((bugs["assigned_to"].astype(str).str.lower() != "unassigned").sum())
triaged_pct = percent(triaged_issues, total_issues)

# Lists: status distribution
STATUS_ORDER = ["NEW", "ASSIGNED", "RESOLVED", "REOPENED"]

status_counts = (
    bugs["bug_status"]
    .astype(str)
    .str.upper()
    .value_counts()
    .reindex(STATUS_ORDER, fill_value=0)
)

status_items = [
    {"label": status, "value": int(count)}
    for status, count in status_counts.items()
]

df_status = status_counts.rename_axis("label").reset_index(name="value")


# -----------------------------
# Layout (3x3)
# -----------------------------
c1, c2, c3 = st.columns(3, gap="large")

# Row 1: Defects (now real)
with c1:
    st.markdown('<div class="section-title">Open defects (GCC Bugzilla)</div>', unsafe_allow_html=True)
    st.caption("Definition: bug_status not in {RESOLVED, CLOSED}. Subsystems = top components by open count.")

with c2:
    st.markdown(f"""
    <div class="tile {defects_status(defects_a, 20)}">
      <div style="font-weight:700;">Component: {comp_a}</div>
      <div style="font-size:42px; font-weight:800;">{defects_a}</div>
      <div class="small">Open bugs in this component</div>
    </div>
    """, unsafe_allow_html=True)

with c3:
    st.markdown(f"""
    <div class="tile {defects_status(defects_b, 20)}">
      <div style="font-weight:700;">Component: {comp_b}</div>
      <div style="font-size:42px; font-weight:800;">{defects_b}</div>
      <div class="small">Open bugs in this component</div>
    </div>
    """, unsafe_allow_html=True)

st.divider()

# Row 2: Progress (resolution + triage)
c1, c2, c3 = st.columns(3, gap="large")
with c1:
    st.markdown('<div class="section-title">Workflow progress</div>', unsafe_allow_html=True)
    st.caption("Interpreted as pipeline KPIs: resolution progress and triage coverage.")

with c2:
    st.subheader("Resolution progress")
    st.progress(resolved_pct / 100)
    st.caption(f"{resolved_issues} of {total_issues} are RESOLVED/CLOSED ({resolved_pct}%)")

with c3:
    st.subheader("Triage coverage")
    st.progress(triaged_pct / 100)
    st.caption(f"{triaged_issues} of {total_issues} have an assignee ({triaged_pct}%)")

st.divider()


# Row 3: Status distribution
c1, c2, c3 = st.columns(3, gap="large")
with c1:
    st.markdown('<div class="section-title">Bug status distribution</div>', unsafe_allow_html=True)
    st.caption("Shows the current state mix. Useful for spotting backlog/throughput issues.")

with c2:
    st.subheader("All statuses (table)")
    st.dataframe(df_status, use_container_width=True, hide_index=True)

with c3:
    st.subheader("All statuses (chart)")

    chart = (
        alt.Chart(df_status)
        .mark_bar()
        .encode(
            x=alt.X("label:N", sort=STATUS_ORDER, title="Status"),
            y=alt.Y("value:Q", title="Count"),
            tooltip=["label", "value"]
        )
    )
    st.altair_chart(chart, use_container_width=True)


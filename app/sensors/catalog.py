from typing import Any

from app.correlator.scoring import STRONG_WEIGHT, weight_for

# What each sensor is, written for the agent that reads its scores. Facts
# come from the model metadata and the integration tests; the live numbers
# (threshold, weight, health) are added at call time, never copied here.
PROFILES: dict[str, dict[str, Any]] = {
    "http_payload_sensor": {
        "purpose": (
            "Flags a single web request whose path and query string look "
            "like an attack: SQL injection, XSS, path traversal, command "
            "injection."
        ),
        "model": "TF-IDF over character 2 to 4 grams plus logistic regression",
        "trained_on": "CSIC 2010 HTTP dataset plus synthetic requests",
        "sees": "the path and query of every request in the nginx log",
        "fed_by": "the nginx log feed on every request (live)",
        "score": "probability that the request is an attack, 0 to 1",
        "limits": [
            "No request body and no method in the nginx log, so attacks in "
            "POST bodies are invisible.",
            "Recall on attack families it never saw in training is only "
            "27 to 62 percent.",
            "It flags some harmless URLs (about 1 in 5 on a hand-made "
            "probe; shop URLs such as category and next= redirects score "
            "0.3 to 0.8), so one hit alone is weak evidence.",
        ],
        "mitre": "T1190 exploit public-facing application",
    },
    "recon_sensor": {
        "purpose": (
            "Detects web directory brute force and scanning: one IP "
            "requesting many different paths that mostly return 404."
        ),
        "model": "XGBoost on 6 features of a 10 second per-IP window",
        "trained_on": (
            "AIT Log Data Set v2.0, 8 replicas of one WordPress scenario "
            "(dirb, wpscan, nmap)"
        ),
        "sees": "per-IP windows of 10 s of path, status and user agent",
        "fed_by": "the nginx log feed, one window per IP (live)",
        "score": "scan probability, saturated: read it as a rank",
        "limits": [
            "Any window of about 5 or more mostly-404 requests is flagged, "
            "so a stale-link crawler or a page with broken assets can "
            "false-alarm.",
            "It does not see low-and-slow scans, credential brute force "
            "that returns 200, 401 or 403, or webshell commands.",
            "Trained on one simulated site; unseen sites are untested.",
        ],
        "mitre": "T1595 active scanning",
    },
    "log_sentinel": {
        "purpose": (
            "Detects abnormal Hadoop HDFS block lifecycles from the "
            "sequence of log event types."
        ),
        "model": "TextCNN (ONNX) over the first 40 events of a block",
        "trained_on": "HDFS_v1 benchmark, events E1 to E29 per block",
        "sees": "a list of event ids such as E5, E22, E11 for one block_id",
        "fed_by": (
            "nothing live yet: only pasted event ids (analyze_input) or "
            "events pushed to the API"
        ),
        "score": "sigmoid of the logit; the threshold is tuned for recall",
        "limits": [
            "Raw Hadoop log lines are not parsed into event ids yet.",
            "An all-unknown sequence scores 0.999, so unmapped logs would "
            "all alert.",
            "The benchmark is easy; expect worse on real logs.",
        ],
        "mitre": None,
    },
    "net_guard": {
        "purpose": (
            "Classifies one network flow as benign or one of 7 attack "
            "categories: Bot, BruteForce, DDoS, DoS, PortScan, WebAttack, "
            "Other."
        ),
        "model": "1D CNN (ONNX) over 77 flow features",
        "trained_on": "CICIDS2017 network intrusion dataset",
        "sees": "CICFlowMeter-style flow features (77 numbers per flow)",
        "fed_by": (
            "nothing live yet: needs a flow collector; only pushed events "
            "or tests today"
        ),
        "score": "1 minus the probability of benign; plus the top class",
        "limits": [
            "No tuned threshold: a flow is anomalous when the top class "
            "is not benign.",
            "About 5 percent of benign test flows are flagged.",
            "The Other class has about 36 training samples and weak "
            "recall.",
            "Test metrics come from a random split, so they are optimistic.",
        ],
        "mitre": None,
    },
    "netflow_sensor": {
        "purpose": (
            "Flags a flow as a web attack (brute force, XSS, SQL "
            "injection) rather than benign."
        ),
        "model": "logistic regression with a standard scaler, 80 features",
        "trained_on": "the CIC-IDS-2017 Thursday web-attack capture only",
        "sees": "CICFlowMeter flow features (80 numbers per flow)",
        "fed_by": (
            "nothing live yet: needs a flow collector; only pushed events "
            "or tests today"
        ),
        "score": "probability of web attack, threshold 0.99",
        "limits": [
            "Destination port dominates the model, so it behaves "
            "port-specifically.",
            "Threshold was chosen on the test split: precision 0.76 at "
            "that point is optimistic.",
            "Only three attack types were in the training data.",
        ],
        "mitre": None,
    },
}

HOW_CASES_ARE_RAISED = (
    "The correlator keeps the best score per sensor for each IP and 60 s "
    "window and takes a weighted mean. Sensors with weight 0.5 or more are "
    "strong. Two strong sensors with a composite of at least 0.6 is high; "
    "one strong sensor at 0.9 or more is medium; three strong sensors at "
    "0.4 or more is high. A window escalates again only when severity "
    "rises."
)


def profile_for(name: str) -> dict[str, Any]:
    base = PROFILES.get(name, {})
    weight = weight_for(name)

    return {
        **base,
        "correlator_weight": weight,
        "counts_as_strong": weight >= STRONG_WEIGHT,
    }

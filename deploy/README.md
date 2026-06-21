# Deploy Templates

This directory contains the minimal observability templates for the Rust rewrite.
Two images ship from this repo and deploy together:

- **caretta-rust** — privileged eBPF DaemonSet (network connections), `hostNetwork`, port 7117. Built from `network/`.
- **caretta-k8s-state** — non-privileged single-instance Deployment (Kubernetes Events), ClusterIP, port 7118. Built from `k8s-state/`.

Both share the `caretta-k8s-core` crate but run with deliberately separate forms and RBAC.

## Files

- [caretta.yaml](caretta.yaml): both workloads in one manifest — each with its own ServiceAccount / ClusterRole / ClusterRoleBinding (least privilege), the DaemonSet, and the Deployment + ClusterIP Service.
- [caretta-grafana-dashboard-configmap.yaml](caretta-grafana-dashboard-configmap.yaml): single dashboard ConfigMap with both the network panels and the Kubernetes Events row.
- [caretta-rust-observability-values.yaml](caretta-rust-observability-values.yaml): Helm-style values template for a Prometheus + Grafana stack.

## How to use

1. Build and push the two images, then update the image references in [caretta.yaml](caretta.yaml).
2. Apply the workloads: `kubectl apply -f deploy/caretta.yaml`.
3. Apply the dashboard: `kubectl apply -f deploy/caretta-grafana-dashboard-configmap.yaml`.
4. Use the values template to configure Prometheus scraping and the Grafana datasource.

## Notes

- The template assumes Prometheus is reachable at `http://prometheus:9090`; adjust the datasource URL if your service name differs.
- The DaemonSet uses `hostNetwork: true`, so each node exposes metrics directly on `NodeIP:7117` (no Service needed). The Event collector is reached through its ClusterIP Service on 7118 with `prometheus.io/scrape` annotations.
- The DaemonSet runs privileged with host networking so eBPF probes can load on each node; the Event collector is unprivileged.
- The ConfigMap is named `caretta-rust-grafana-dashboards` and carries the `grafana_dashboard=1` label required by the sidecar; the dashboard is mounted as `default-dashboard.json`.
- The Events panels read `caretta_k8s_events_total`, a counter holding aggregated counts per `(namespace, type, reason, workload_kind, workload_name)` — no per-event message text. The "Recent Events" table is therefore counts-over-window, not a raw event log (a true log stream would need Loki).

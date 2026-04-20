# Deploy Templates

This directory contains the minimal observability template for the Rust rewrite.

## Files

- [caretta-rust-observability-values.yaml](caretta-rust-observability-values.yaml): Helm-style values template for a Prometheus + Grafana stack.
- [caretta-rust-grafana-dashboard-configmap.yaml](caretta-rust-grafana-dashboard-configmap.yaml): Ready-to-apply ConfigMap with embedded dashboard JSON.
- [caretta-rust-k8s.yaml](caretta-rust-k8s.yaml): Minimal DaemonSet, RBAC, and hostNetwork metrics endpoint for Kubernetes deployment.

## How to use

1. Build and push a Caretta Rust image, then replace the image reference in [caretta-rust-k8s.yaml](caretta-rust-k8s.yaml).
2. Apply the runtime manifest with `kubectl apply -f deploy/caretta-rust-k8s.yaml`.
3. Apply the dashboard ConfigMap with `kubectl apply -f deploy/caretta-rust-grafana-dashboard-configmap.yaml`.
4. Use the values template to configure Prometheus scraping and Grafana datasource settings.
5. If you want to reuse the existing caretta-go dashboard JSON, validate the Prometheus label names first. The Rust version keeps the core metric names aligned.
6. The ConfigMap is named `caretta-rust-grafana-dashboards` and carries the `grafana_dashboard=1` label required by the sidecar.

## Notes

- The template assumes Prometheus is reachable at `http://prometheus:9090`.
- If your Prometheus service name differs, update the datasource URL.
- The DaemonSet uses `hostNetwork: true`, so each node exposes the metrics endpoint directly on `NodeIP:7117`; Prometheus can scrape those node IPs without a ClusterIP Service.
- If your stack already uses the Prometheus Operator, use PodMonitor or equivalent pod-based discovery against `NodeIP:7117` instead of a ServiceMonitor.
- The dashboard file is mounted as `default-dashboard.json`, which matches the Grafana home-dashboard path in the values template.
- The DaemonSet runs privileged with host networking so eBPF probes can load on each node.

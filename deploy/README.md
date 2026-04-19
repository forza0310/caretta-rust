# Deploy Templates

This directory contains the minimal observability template for the Rust rewrite.

## Files

- [caretta-rust-observability-values.yaml](caretta-rust-observability-values.yaml): Helm-style values template for a Prometheus + Grafana stack.
- [caretta-rust-grafana-dashboard-configmap.yaml](caretta-rust-grafana-dashboard-configmap.yaml): Ready-to-apply ConfigMap with embedded dashboard JSON.

## How to use

1. Deploy the Rust Caretta workload with the `app=caretta-rust` label and expose `/metrics` on port `7117`.
2. Use the values template to configure Prometheus scraping and Grafana datasource settings.
3. Apply the dashboard ConfigMap with `kubectl apply -f deploy/caretta-rust-grafana-dashboard-configmap.yaml`.
4. If you want to reuse the existing caretta-go dashboard JSON, validate the Prometheus label names first. The Rust version keeps the core metric names aligned.
5. The ConfigMap is named `caretta-rust-grafana-dashboards` and carries the `grafana_dashboard=1` label required by the sidecar.

## Notes

- The template assumes Prometheus is reachable at `http://prometheus:9090`.
- If your Prometheus service name differs, update the datasource URL.
- For in-cluster scraping, a ServiceMonitor is also fine if your stack already uses the Prometheus Operator.
- The dashboard file is mounted as `default-dashboard.json`, which matches the Grafana home-dashboard path in the values template.

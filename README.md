# LLOYD-AARIN: Neuro-Symbolic Kinetic Interdiction
**AI Hackathon 2025 Submission**

## Abstract
Lloyd-Aarin closes the "Interdiction Gap" in Critical Infrastructure security. It combines:
1. **System 1 (Reflex):** eBPF/XDP for microsecond packet dropping.
2. **System 2 (Brain):** PyTorch Autoencoder for zero-day detection.
3. **Swarm:** UDP Gossip protocol for distributed immunity.

## Architecture
- **Kernel:** Rust + Aya (XDP)
- **AI:** Python + PyTorch
- **Bus:** Apache Kafka
- **Swarm:** UDP Multicast

## Usage
1. Run Gateway: `cargo run --bin gateway`
2. Run AI: `docker run lloyd-brain`

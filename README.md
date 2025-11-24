LLOYD AARIN Defence Systems

Neuro-Symbolic Kinetic Interdiction for Critical Infrastructure.

Contact: waa6673@nyu.edu

LLOYD Aarin combines the speed of Kernel-level interdiction (eBPF XDP) with the adaptability of Deep Learning (PyTorch Autoencoders) to detect and block Zero-Day IoT attacks in <800ms.

🏗 Architecture

System 1 (Reflex): Rust + eBPF XDP Sensor.

System 2 (Cognitive): PyTorch "Chimera" Neural Network.

Nervous System: Kafka Message Bus.

Muscle: Kinetic Interdiction via BPF HashMaps.

🚀 Deployment

docker compose up --build -d

Verify System 1: docker compose logs -f lloyd-parser

Verify System 2: docker compose logs -f chimera
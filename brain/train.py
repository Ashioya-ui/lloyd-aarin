import torch, torch.optim as optim, torch.nn as nn
from model import PacketAutoencoder
def train_baseline():
    model = PacketAutoencoder(7)
    torch.save(model.state_dict(), "chimera_brain.pth")
    print("💾 Brain Initialized.")

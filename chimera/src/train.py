import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
from model import PacketAutoencoder
import logging
logging.basicConfig(level=logging.INFO)
def train_baseline():
    model = PacketAutoencoder(input_dim=5)
    criterion = nn.MSELoss()
    optimizer = optim.Adam(model.parameters(), lr=0.001)
    data = []
    for _ in range(5000):
        data.append([np.random.randint(1024,65535)/65535.0, np.random.choice([1883,80,443])/65535.0, 1.0, np.random.normal(100,20)/1500.0, np.random.rand()])
    X_train = torch.tensor(data, dtype=torch.float32)
    for epoch in range(20):
        optimizer.zero_grad()
        loss = criterion(model(X_train), X_train)
        loss.backward()
        optimizer.step()
    torch.save(model.state_dict(), "/app/chimera_brain.pth")
    logging.info("🧠 CHIMERA: Brain Trained & Saved.")
if __name__ == "__main__": train_baseline()
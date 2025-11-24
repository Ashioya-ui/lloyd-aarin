import torch
import torch.nn as nn
class PacketAutoencoder(nn.Module):
    def __init__(self, input_dim=5):
        super(PacketAutoencoder, self).__init__()
        self.encoder = nn.Sequential(nn.Linear(input_dim, 12), nn.ReLU(), nn.Linear(12, 8), nn.ReLU(), nn.Linear(8, 3))
        self.decoder = nn.Sequential(nn.Linear(3, 8), nn.ReLU(), nn.Linear(8, 12), nn.ReLU(), nn.Linear(12, input_dim), nn.Sigmoid())
    def forward(self, x): return self.decoder(self.encoder(x))
import torch.nn as nn
class PacketAutoencoder(nn.Module):
    def __init__(self, input_dim=7):
        super().__init__()
        self.encoder = nn.Sequential(nn.Linear(input_dim, 16), nn.ReLU(), nn.Linear(16, 3))
        self.decoder = nn.Sequential(nn.Linear(3, 16), nn.ReLU(), nn.Linear(16, input_dim), nn.Sigmoid())
    def forward(self, x): return self.decoder(self.encoder(x))

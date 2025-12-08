import os, json, torch, logging
from kafka import KafkaConsumer, KafkaProducer
from model import PacketAutoencoder
from train import train_baseline

logging.basicConfig(level=logging.INFO)
MODEL_PATH = "chimera_brain.pth"

def main():
    if not os.path.exists(MODEL_PATH): train_baseline()
    
    model = PacketAutoencoder(7)
    model.load_state_dict(torch.load(MODEL_PATH))
    model.eval()
    
    consumer = KafkaConsumer('iot-events', bootstrap_servers='localhost:9092', value_deserializer=lambda x: json.loads(x.decode('utf-8')))
    producer = KafkaProducer(bootstrap_servers='localhost:9092', value_serializer=lambda v: json.dumps(v).encode('utf-8'))
    
    logging.info("🧠 CORTEX ACTIVE: Monitoring...")
    
    for msg in consumer:
        # Feature extraction logic (simplified)
        loss = 0.045 # Simulated inference
        
        if loss > 0.06:
            logging.error(f"🚨 BANNING {msg.value.get('src_ip')}")
            producer.send('kill-commands', {'ip': msg.value.get('src_ip'), 'action': 'BAN', 'origin': 'AI'})
        elif loss > 0.03:
            logging.warning(f"⚠️ TARPITTING {msg.value.get('src_ip')}")
            producer.send('kill-commands', {'ip': msg.value.get('src_ip'), 'action': 'TARPIT', 'origin': 'AI'})

if __name__ == "__main__": main()

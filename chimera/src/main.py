import os, json, time, torch, torch.nn as nn, logging
from kafka import KafkaConsumer, KafkaProducer
from model import PacketAutoencoder
from train import train_baseline

KAFKA_BROKER = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
logging.basicConfig(format='%(asctime)s [CHIMERA] %(levelname)s: %(message)s', level=logging.INFO)

def main():
    if not os.path.exists("/app/chimera_brain.pth"): train_baseline()
    model = PacketAutoencoder(5)
    model.load_state_dict(torch.load("/app/chimera_brain.pth"))
    model.eval()
    criterion = nn.MSELoss()
    
    consumer = KafkaConsumer('iot-events', bootstrap_servers=KAFKA_BROKER, value_deserializer=lambda x: json.loads(x.decode('utf-8')), group_id='chimera-group')
    producer = KafkaProducer(bootstrap_servers=KAFKA_BROKER, value_serializer=lambda v: json.dumps(v).encode('utf-8'))
    
    logging.info("🧠 CHIMERA Cortex Active.")
    for message in consumer:
        evt = message.value
        try:
            features = torch.tensor([[evt.get('src_port',0)/65535.0, evt.get('dst_port',0)/65535.0, 1.0, evt.get('len',0)/1500.0, 0.5]], dtype=torch.float32)
            loss = criterion(model(features), features).item()
            if loss > 0.05:
                logging.warning(f"🚨 ANOMALY DETECTED (Loss: {loss:.4f}) from {evt.get('src_ip')}")
                producer.send('kill-commands', {"ip": evt.get('src_ip'), "action": "BAN", "reason": f"AI_Anomaly_{loss:.2f}"})
        except: pass

if __name__ == "__main__": main()
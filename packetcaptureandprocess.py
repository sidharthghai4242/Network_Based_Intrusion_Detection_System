import tensorflow as tf
import numpy as np
from scapy.all import sniff, IP, TCP, UDP  # Import IP layer explicitly
import tkinter as tk
from tkinter import messagebox

# Load your trained model (assuming it's saved as 'ism_model.keras')
model = tf.keras.models.load_model('ism_model.keras')

# Define batch size for batch prediction (not strictly needed here)
BATCH_SIZE = 10
packet_buffer = []

# List of specific IPs to monitor (replace with your desired IP addresses)
monitored_ips = ["192.168.10.188", "10.0.0.2"]

def capture_packets(interface='Wi-Fi'):
    """Continuously captures packets, processes only IP packets from monitored IPs, and buffers them."""
    try:
        while True:
            packets = sniff(iface=interface, count=1, filter="ip")  # Capture packets (list)
            for packet in packets:  # Iterate through captured packets
                if packet[IP].src in monitored_ips or packet[IP].dst in monitored_ips:
                    process_packet(packet)  # Process each packet individually
    except KeyboardInterrupt:
        print("Exiting packet capture...")

def process_packet(packet):
    """Preprocesses a single packet and makes predictions."""
    features = np.array(preprocess_data(packet))  # Extract features
    prediction = model.predict(np.expand_dims(features, axis=0))[0]  # Predict for single packet

    # Set a threshold and handle prediction (correct the comparison)
    threshold = 0.5
    if prediction[0] > threshold:  # Access the first element (assuming single prediction)
        generate_alert([packet], [prediction], threshold)  # Generate alert for single packet


def generate_alert(packet_buffer, predictions, threshold):
    """Displays an alert message box with attack information for monitored IPs."""
    alert_message = "Potential attack detected on monitored IPs!\n\n"
    for packet, prediction in zip(packet_buffer, predictions):
        # Check if this packet belongs to a monitored IP
        if packet[IP].src in monitored_ips or packet[IP].dst in monitored_ips:
            alert_message += f"Packet details: {packet.summary()}\n"
            alert_message += f"Prediction: {prediction}\n"

            # Add reason for the alert based on prediction
            if prediction > threshold:
                alert_message += "Reason: Suspicious activity detected.\n\n"
            else:
                alert_message += "Reason: Normal network traffic.\n\n"

    root = tk.Tk()
    root.withdraw()  # Hide the main window
    messagebox.showwarning("Potential Attack Detected", alert_message)

def preprocess_data(packet):
    """Extracts relevant features from the packet for model input."""
    features = []

    if IP in packet:
        # Extract IP features (consider adding more as needed)
        duration = packet.time - packet.payload.time
        features.append(duration)

        # Protocol one-hot encoding
        protocol = packet.payload.name
        protocols = ['tcp', 'udp', 'icmp', 'arp']
        protocol_encoding = [1 if protocol == p else 0 for p in protocols]
        features.extend(protocol_encoding)

        # Extract port information (if applicable)
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            src_port = 0
            dst_port = 0
        features.append(src_port)
        features.append(dst_port)

        # Packet length
        length = len(packet)
        features.append(length)

    # Add more features based on your model's requirements
    while len(features) < 196:  # Assuming your model expects 196 features
        features.append(0)  # Pad with zeros

    return np.array(features)

# Example usage (replace with your interface name if needed)
capture_packets(interface='Wi-Fi')

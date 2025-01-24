import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Generate RSA Keys (for demonstration purposes)
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# Serialize keys to PEM format
def serialize_key(key, is_private=False):
    if is_private:
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

# Encrypt a packet with a public key
def encrypt_packet(packet, public_key):
    return public_key.encrypt(
        packet.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# Create an onion-encrypted packet
def create_onion_packet(packet_data, public_keys):
    current_layer = json.dumps(packet_data)
    for key in reversed(public_keys):
        current_layer = encrypt_packet(current_layer, key)
    return current_layer

# Save encrypted packet to a file
def save_encrypted_packet(file_path, encrypted_packet):
    with open(file_path, "wb") as f:
        f.write(encrypted_packet)
    print(f"Encrypted packet saved to {file_path}")

# Main
if __name__ == "__main__":
    # Generate keys for 3 layers
    layers = 3
    keys = [generate_rsa_keys() for _ in range(layers)]
    private_keys, public_keys = zip(*keys)

    # Serialize and save keys (optional, for distribution)
    for i, (priv, pub) in enumerate(keys):
        with open(f"private_key_{i}.pem", "wb") as f:
            f.write(serialize_key(priv, is_private=True))
        with open(f"public_key_{i}.pem", "wb") as f:
            f.write(serialize_key(pub))

    # Create a sample packet
    packet_data = {
        "header": "Level 8 Security",
        "payload": "This is a highly secure onion-encrypted packet.",
        "metadata": {"timestamp": "2025-01-08T12:00:00Z"}
    }
    onion_packet = create_onion_packet(packet_data, public_keys)
    print("Onion-encrypted packet created.")

    # Save the encrypted packet to a file
    save_encrypted_packet("encrypted_packet.bin", onion_packet)

import os
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from tkinter import Tk, filedialog

# Custom decryption function (AES in this example)
def decrypt_packet(encrypted_packet, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_packet) + decryptor.finalize()

# Load packets from file
def load_packets(file_path):
    with open(file_path, "rb") as f:
        return f.read()

# Save reconstructed packets to a file
def save_reconstructed_packets(output_path, packets):
    with open(output_path, "w") as f:
        json.dump(packets, f, indent=4)
    print(f"Reconstructed packets saved to {output_path}")

# Process packets in a file
def process_packets(file_path, key, iv):
    print(f"Processing file: {file_path}")
    encrypted_data = load_packets(file_path)
    decrypted_data = decrypt_packet(encrypted_data, key, iv)

    # Assuming the decrypted data is a JSON array of packets
    try:
        packets = json.loads(decrypted_data)
        print(f"Decrypted and parsed {len(packets)} packets.")
        return packets
    except json.JSONDecodeError:
        print("Failed to decode decrypted data. Ensure it is in JSON format.")
        return []

# GUI for file selection
def select_files():
    root = Tk()
    root.withdraw()  # Hide the root window
    file_paths = filedialog.askopenfilenames(title="Select Files to Upload")
    return file_paths

# Main function
def main():
    # AES key and IV (example values, replace with your actual key and IV)
    key = b"your_16_byte_key"
    iv = b"your_16_byte_iv"

    # Select files for processing
    file_paths = select_files()
    if not file_paths:
        print("No files selected.")
        return

    reconstructed_packets = []

    # Process each file
    for file_path in file_paths:
        packets = process_packets(file_path, key, iv)
        if packets:
            reconstructed_packets.extend(packets)

    # Save the reconstructed packets
    if reconstructed_packets:
        output_path = filedialog.asksaveasfilename(
            title="Save Reconstructed Packets",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if output_path:
            save_reconstructed_packets(output_path, reconstructed_packets)
        else:
            print("Save operation canceled.")
    else:
        print("No packets were reconstructed.")

if __name__ == "__main__":
    main()

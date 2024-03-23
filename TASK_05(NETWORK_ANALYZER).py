import tkinter as tk
from tkinter import scrolledtext
import threading
import scapy.all as scapy
class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")
        self.root.configure(bg="#1f2833")
        self.start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing, bg="#45a29e", fg="white", font=("Helvetica", 12), bd=0, padx=10, pady=5)
        self.start_button.pack(pady=5)
        self.stop_button = tk.Button(root, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED, bg="#e74c3c", fg="white", font=("Helvetica", 12), bd=0, padx=10, pady=5)
        self.stop_button.pack(pady=5)
        self.output_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=60, height=20, bg="#2c3e50", fg="#ffffff", font=("Courier New", 10))
        self.output_text.pack(padx=10, pady=5)
        self.status_bar = tk.Label(root, text="Ready", bd=0, relief=tk.FLAT, anchor=tk.W, bg="#1f2833", fg="#ffffff", font=("Helvetica", 10))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.sniffing_thread = None
        self.sniffing = False

    def start_sniffing(self):
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.sniffing = True
        self.status_bar.config(text="Sniffing...", fg="#45a29e")
        self.sniffing_thread = threading.Thread(target=self.start_sniffing_thread)
        self.sniffing_thread.start()

    def start_sniffing_thread(self):
        scapy.sniff(prn=self.packet_callback, store=0, stop_filter=self.stop_sniffing_condition)
        self.status_bar.config(text="Ready", fg="#ffffff")

    def stop_sniffing(self):
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.sniffing = False
        self.status_bar.config(text="Sniffing stopped", fg="#e74c3c")

    def stop_sniffing_condition(self, packet):
        return not self.sniffing

    def packet_callback(self, packet):
        if scapy.IP in packet:
            self.output_text.insert(tk.END, "--------------------------------------\n")
            self.output_text.insert(tk.END, "IP Addresses:\n")
            self.output_text.insert(tk.END, f"Source IP: {packet[scapy.IP].src}\n")
            self.output_text.insert(tk.END, f"Destination IP: {packet[scapy.IP].dst}\n")
            self.output_text.insert(tk.END, "Protocol:\n")
            self.output_text.insert(tk.END, f"Protocol: {packet[scapy.IP].proto}\n")
            self.output_text.insert(tk.END, "Packet Headers:\n")
            for layer in packet.layers():
                self.output_text.insert(tk.END, f"\t{layer.name}\n")
            self.output_text.insert(tk.END, "Payload:\n")
            self.print_payload(packet)
            self.output_text.insert(tk.END, "\n")
            self.output_text.see(tk.END) 

    def print_payload(self, packet):
        if scapy.TCP in packet:
            try:
                payload = packet[scapy.Raw].load.decode('utf-8', 'ignore')
                self.output_text.insert(tk.END, f"TCP Payload: {payload}\n")
            except Exception as e:
                self.output_text.insert(tk.END, f"Error decoding TCP payload: {e}\n")
        elif scapy.UDP in packet:
            try:
                payload = packet[scapy.Raw].load.decode('utf-8', 'ignore')
                self.output_text.insert(tk.END, f"UDP Payload: {payload}\n")
            except Exception as e:
                self.output_text.insert(tk.END, f"Error decoding UDP payload: {e}\n")
        elif scapy.Raw in packet:
            payload = packet[scapy.Raw].load
            self.output_text.insert(tk.END, f"Other Payload: {payload.hex()}\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()
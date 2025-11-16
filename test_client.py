# test_client.py - simple Python test client to send commands to honeypot
import socket, time

HOST = "127.0.0.1"
PORT = 2229  # adjust if your honeypot bound to different port

def send(cmd):
    try:
        s = socket.create_connection((HOST, PORT), timeout=3)
        # read possible banner line
        try:
            banner = s.recv(1024).decode(errors="ignore")
            print("BANNER:", banner.strip())
        except Exception:
            pass
        s.sendall((cmd + "\n").encode())
        time.sleep(0.2)
        try:
            resp = s.recv(4096).decode(errors="ignore")
            print("RESP:", resp.strip())
        except Exception:
            pass
        s.close()
    except Exception as e:
        print("Failed to send:", e)

if __name__ == "__main__":
    for c in ["ls", "whoami", "sudo apt update", "nmap -sV 127.0.0.1", "rm -rf /"]:
        print("=>", c)
        send(c)
        time.sleep(0.4)

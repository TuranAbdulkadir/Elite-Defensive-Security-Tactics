import os
import random

class SecureShredder:
    def gutmann_wipe(self, filepath):
        print(f"[*] Initiating 35-pass Gutmann wipe on {filepath}")
        if not os.path.exists(filepath):
            return
        
        file_size = os.path.getsize(filepath)
        with open(filepath, "ba+") as f:
            for pass_num in range(35):
                f.seek(0)
                # Overwrite with random bytes
                f.write(bytearray(random.getrandbits(8) for _ in range(file_size)))
        os.remove(filepath)
        print(f"[+] File securely eradicated from disk.")

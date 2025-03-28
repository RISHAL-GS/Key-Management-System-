# Key Management System (KMS)

## Overview
The **Key Management System (KMS)** is a Python-based system that securely generates, manages, and revokes cryptographic keys. It supports AES, RSA, and Diffie-Hellman (DH) key management, certificate generation, and revocation.

## Features
- **AES Key Generation & Storage**
- **RSA Key Pair Generation**
- **Diffie-Hellman Key Exchange for Secure Key Sharing**
- **Self-Signed Certificate Generation**
- **Certificate Verification & Revocation**
- **Secure AES Key Encryption & Transmission**
- **Certificate Revocation List (CRL) Management**

---

## Installation

1. Install Python (if not already installed). if you want to use this codes.
2. you can also run this on google collab.
3. Install required dependencies:

   ```sh
   pip install cryptography
   ```
4. Run the script:
   ```sh
   python kms.py
   ```

---

## Usage Guide
## BRIEF ABOUT USAGE
IF YOU ARE USING SYMMETRIC ENCRYPTION THEN
**->CHOOSE GENERATE AES KEY THEN**
**-->CHOOSE DIFFI HELLMAN OPTION THEN INPUT THE USER ID**
**-->YOU CAN TRANSMIT IT THROUGH CHOOSING THE ENCRYPTION OPTION AND SEND IT TO RECIEVER**
**INPUT THE SENDER AND RECIEVER USER ID THEN THE KEY WHICH YOU WANT TO SEND AND RECIEVER END ALSO SAME SENDER AND RECIEVER AND THE SAME KEY AND YOU WILL GET IT DECRYPTED**
### 1. Generating an AES Key
**Input:**
```
Enter AES Key ID: key1
```
**Output:**
```
AES Key for key1: <hexadecimal key>
AES Key generated successfully.
```

### 2. Generating an RSA Key Pair
**Input:**
```
Enter RSA User ID: user1
```
**Output:**
```
RSA Key Pair generated successfully.
```

### 3. Generating a Self-Signed Certificate
**Input:**
```
Enter User ID for Certificate: user1
```
**Output:**
```
Self-Signed Certificate generated successfully.
```

### 4. Generating a Diffie-Hellman Shared Key
**Input:**
```
Enter User A ID: userA
Enter User B ID: userB
```
**Output:**
```
Generating DH key pair for userA...
Generating DH key pair for userB...
Shared AES Key Derived Successfully.
```

### 5. Verifying a Certificate
**Input:**
```
Enter User ID to Verify Certificate: user1
```
**Output:**
```
✅ Certificate is valid.
```

### 6. Revoking a Key
**Input:**
```
Enter key type (AES/RSA/Certificate/DH): RSA
Enter key ID to revoke: user1
```
**Output:**
```
RSA key pair for user1 revoked.
```

### 7. Encrypting and Sending an AES Key
**Input:**
```
Enter Sender ID: userA
Enter Receiver ID: userB
Enter AES Key ID: key1
```
**Output:**
```
Encrypted AES Key: <hexadecimal encrypted key>
Encrypted AES key stored successfully.
```

### 8. Receiving and Decrypting an AES Key
**Input:**
```
Enter Sender ID: userA
Enter Receiver ID: userB
Enter AES Key ID: key1
```
**Output:**
```
Decrypted AES Key: <hexadecimal key>
```

### 9. Exiting
**Input:**
```
9
```
**Output:**
```
Exiting...
```

---

## File Structure
```
key_storage/               # Stores generated keys & certificates
  ├── key1_aes.key         # Stored AES key
  ├── user1_private.pem    # RSA private key
  ├── user1_public.pem     # RSA public key
  ├── user1_cert.crt       # Self-signed certificate
  ├── revoked_certificates.txt # List of revoked certificates
  ├── root_crl.pem         # Certificate Revocation List (CRL)
```

---

## Security Considerations
- **AES encryption uses CBC mode** with proper padding.
- **RSA keys are securely generated** and stored in PEM format.
- **Diffie-Hellman ensures secure key exchange** for AES keys.
- **Certificates can be revoked**, and CRLs are updated dynamically.
- **Keys are securely stored** in the `key_storage/` directory.
 
---

## License
This project is licensed under the MIT License.

---

## Run on Google Colab
You can also run this project on Google Colab by clicking the button below:

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/drive/1-CHgtq-UTkTVEFRW02IXPGU2Hwv60Rg_?usp=sharing)


## Author
**Rishal G shriyan**



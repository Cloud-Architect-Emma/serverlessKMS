# AWS KMS Serverless Encryption Project

## Overview

This project demonstrates how to securely **encrypt and decrypt user notes** using **AWS Key Management Service (KMS)** integrated with a **serverless architecture** using **AWS Lambda** and **DynamoDB**.

- Notes are encrypted using a **customer managed symmetric CMK (Customer Master Key)** in KMS.
- Encrypted notes and encrypted data keys are stored securely in DynamoDB.
- Decryption occurs in Lambda using KMS.
- No API Gateway used — interaction with Lambda happens through AWS Console test events or SDK.

---

## Architecture Diagram    

![System Architecture Diagram](serverless%20KMS.JPG)             


---

## Components

- **AWS KMS** — Manages encryption keys and performs cryptographic operations.
- **AWS Lambda** — Serverless compute to perform encryption and decryption logic.
- **AWS DynamoDB** — NoSQL database to store encrypted notes along with encrypted keys.
- **IAM Role** — Grants Lambda permission to access KMS and DynamoDB.

---

## Features

- Encrypt notes with a customer-managed KMS symmetric key.
- Store encrypted note and encrypted data key in DynamoDB.
- Retrieve and decrypt notes securely in Lambda.
- Simple, secure serverless encryption app without exposing an API.

---

## Setup Instructions

### 1. Create a KMS Customer Managed Key (CMK)

- Create a symmetric key in AWS KMS.
- Set key administrators and users with appropriate permissions.

### 2. Create DynamoDB Table

- Table name: `EncryptedUserNotes`
- Partition key: `user_id` (String)

### 3. Create IAM Role for Lambda

- Permissions:
  - `kms:Encrypt`, `kms:Decrypt`, `kms:GenerateDataKey` on your CMK.
  - `dynamodb:PutItem`, `dynamodb:GetItem` on `EncryptedUserNotes` table.
  - CloudWatch Logs permissions for Lambda logging.

### 4. Create Lambda Function

- Runtime: Python 3.9+
- Attach the IAM role created.
- Set environment variables:
- `TABLE_NAME = EncryptedUserNotes`
- `KMS_KEY_ID = <Your KMS Key ID>`

### 5. Deploy Lambda Code

Use the provided Lambda code (in `lambda_function.py`) to encrypt, store, retrieve, and decrypt notes.

---

## Testing Lambda

Use the AWS Console Lambda test feature with event JSON:

**To store a note:**

```json
{
  "action": "store",
  "user_id": "user123",
  "note": "My secret note stored securely"
}
To retrieve a note:

json
Copy
Edit
{
  "action": "retrieve",
  "user_id": "user123"
}
Code Snippet (Lambda function core)
python
Copy
Edit
import boto3
import base64
import os

kms_client = boto3.client('kms')
dynamodb = boto3.resource('dynamodb')
TABLE_NAME = os.environ['TABLE_NAME']
KEY_ID = os.environ['KMS_KEY_ID']
table = dynamodb.Table(TABLE_NAME)

def encrypt_data(plaintext):
    response = kms_client.generate_data_key(KeyId=KEY_ID, KeySpec='AES_256')
    plaintext_key = response['Plaintext']
    encrypted_key = response['CiphertextBlob']

    ciphertext = base64.b64encode(plaintext.encode()).decode()

    return {
        'ciphertext': ciphertext,
        'encrypted_data_key': base64.b64encode(encrypted_key).decode()
    }

def decrypt_data(ciphertext, encrypted_data_key):
    encrypted_key_bytes = base64.b64decode(encrypted_data_key)
    response = kms_client.decrypt(CiphertextBlob=encrypted_key_bytes)
    plaintext_key = response['Plaintext']

    plaintext = base64.b64decode(ciphertext).decode()
    return plaintext

def lambda_handler(event, context):
    action = event.get('action')
    user_id = event.get('user_id')
    
    if action == 'store':
        note = event.get('note')
        enc_result = encrypt_data(note)
        table.put_item(Item={
            'user_id': user_id,
            'encrypted_note': enc_result['ciphertext'],
            'encrypted_data_key': enc_result['encrypted_data_key']
        })
        return {'message': 'Note encrypted and stored'}
    
    elif action == 'retrieve':
        response = table.get_item(Key={'user_id': user_id})
        item = response.get('Item')
        if not item:
            return {'message': 'Note not found'}
        decrypted_note = decrypt_data(item['encrypted_note'], item['encrypted_data_key'])
        return {'decrypted_note': decrypted_note}
    
    else:
        return {'message': 'Invalid action'}
Notes
This project uses AWS Console only — no API Gateway or external API.

Encryption here uses base64 for demonstration; in production, use proper AES encryption with the data key.

Ensure your IAM roles have correct permissions for KMS and DynamoDB.

Next Steps
Add API Gateway to expose the Lambda via REST API.

Improve encryption using symmetric AES encryption with Python libraries.

Add user authentication to secure note access.

## License
MIT License

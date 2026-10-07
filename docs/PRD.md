# Scam Shield — Product Requirements Document

## 1. Project Overview

Scam Shield is an open-source multimodal AI safety assistant designed to help users identify, understand, and respond safely to potential online scams.

The system will analyze suspicious text and visual evidence such as screenshots and payment-related images. Gemma will be used as the core multimodal reasoning component.

The system is designed to provide decision support rather than guarantee whether content is legitimate.

---

## 2. Problem Statement

Online scams increasingly use realistic messages, impersonation, urgency, fake payment requests, QR codes, phishing links, and social engineering.

Users may receive suspicious content through:

- SMS
- WhatsApp and other messaging platforms
- Email
- Social media
- Online marketplaces
- Payment applications

A user may recognize that something feels suspicious but not understand exactly why.

Scam Shield aims to provide an accessible safety layer that analyzes suspicious content and explains the evidence behind its assessment.

---

## 3. Goals

### Primary Goals

1. Analyze suspicious scam-related content using Gemma.
2. Support both text and image inputs.
3. Detect common scam indicators.
4. Produce an explainable risk assessment.
5. Provide safe and practical recommendations.
6. Communicate uncertainty rather than claiming perfect accuracy.
7. Evaluate performance using a reproducible dataset.

### Secondary Goals

1. Support Indian scam scenarios.
2. Support UPI/payment-related scams.
3. Support Hindi and Hinglish inputs.
4. Provide an accessible web interface.
5. Maintain an auditable open-source development process.

---

## 4. Non-Goals

Scam Shield will not:

- Guarantee that a message is legitimate.
- Make financial decisions on behalf of users.
- Automatically block or report users.
- Automatically send money.
- Request OTPs, passwords, UPI PINs, private keys, or other credentials.
- Replace banks, law enforcement, cybersecurity professionals, or official verification channels.

---

## 5. Target Users

Scam Shield is intended for:

- General internet users
- Students
- Senior citizens
- Digital payment users
- Users receiving suspicious messages
- Users who are unsure whether a payment request is legitimate

---

## 6. Core User Journey

```text
User provides suspicious content
            |
            v
     Input Processing
            |
            v
      Gemma Analysis
            |
            v
    Scam Signal Extraction
            |
            v
      Risk Assessment
            |
            v
  Explanation + Evidence
            |
            v
    Safety Recommendations
            |
            v
        User Decision
# Scam Shield — System Architecture

## 1. Overview

Scam Shield is a multimodal AI-powered scam detection and prevention system.

The system accepts suspicious content such as text messages and screenshots, analyzes the content using Gemma, extracts scam indicators, calculates a risk level, and provides an explanation with recommended safety actions.

The architecture is designed so that Gemma is an important part of the analysis pipeline while additional validation and rule-based checks help reduce incorrect or unsafe recommendations.

---

## 2. High-Level Architecture

```text
                    ┌─────────────────────┐
                    │       USER          │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │    WEB INTERFACE    │
                    │                     │
                    │  • Text input       │
                    │  • Image upload     │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   INPUT PROCESSOR   │
                    │                     │
                    │ • Validate input    │
                    │ • Prepare image     │
                    │ • Normalize text    │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │      GEMMA 4        │
                    │                     │
                    │ Multimodal Analysis │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  SIGNAL EXTRACTION  │
                    │                     │
                    │ • Urgency           │
                    │ • Payment request   │
                    │ • Impersonation     │
                    │ • Phishing          │
                    │ • Social engineering│
                    └──────────┬──────────┘
                               │
                 ┌─────────────┴─────────────┐
                 │                           │
                 ▼                           ▼
        ┌─────────────────┐        ┌─────────────────┐
        │  RULE ENGINE    │        │  RISK ENGINE    │
        │                 │        │                 │
        │ Known patterns  │───────►│ Combine signals │
        │ URL indicators  │        │ and evidence    │
        └─────────────────┘        └────────┬────────┘
                                           │
                                           ▼
                                ┌─────────────────────┐
                                │    SAFETY LAYER     │
                                │                     │
                                │ Validate response   │
                                │ Check recommendations│
                                └──────────┬──────────┘
                                           │
                                           ▼
                                ┌─────────────────────┐
                                │  EXPLANATION LAYER  │
                                │                     │
                                │ • Risk level        │
                                │ • Evidence          │
                                │ • Explanation       │
                                │ • Recommended action│
                                └──────────┬──────────┘
                                           │
                                           ▼
                                ┌─────────────────────┐
                                │    USER RESULT      │
                                └─────────────────────┘
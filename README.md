# 🛡️ PhishGuard — AI-Assisted Phishing URL Detection

PhishGuard is a web-based phishing URL detection system that analyzes suspicious URLs using **machine learning and security heuristics**.

The application extracts structural characteristics from a URL, uses a **Random Forest classifier** to identify phishing patterns, and combines the ML prediction with interpretable security checks to produce a final **threat score from 0–100**.

The system also explains why a URL was considered suspicious and provides security recommendations to the user.

---

## 🚀 Live Demo

### 🌐 Web Application

https://phishing-detection-gray.vercel.app/

### 🎥 Demo Video


https://youtu.be/5QieBst4HI0?si=fCUMCHrJzKOW4Gsn

---

## 📌 Features

* 🔍 URL phishing detection
* 🤖 Machine-learning based classification
* 🛡️ Security heuristic analysis
* 📊 Threat score from 0–100
* 🚦 Risk levels: Low, Medium, High and Critical
* 💡 Explainable detection reasons
* 🔎 URL forensic analysis
* 📋 Recent scan history
* 🔔 Security alert for high-risk URLs
* ⚡ React single-page application
* 🔗 REST API using Flask

---

## 🧠 How It Works

PhishGuard follows a hybrid detection pipeline:

```text
User enters URL
       ↓
React Frontend
       ↓
Flask REST API
       ↓
URL Normalization
       ↓
Feature Extraction
       ↓
Random Forest ML Model
       ↓
Security Heuristics
       ↓
Threat Scoring Engine
       ↓
Risk Level + Explanation
       ↓
React Dashboard
```

---

## 🔬 Machine Learning

The project uses a **Random Forest Classifier** trained on the **PhiUSIIL Phishing URL Dataset**.

The dataset contains approximately **235,000 URLs** and 56 original columns.

For the final model, 29 URL-related numerical features are extracted and used for classification.

### Important Features

Some of the features include:

* URL length
* Domain length
* Path length
* Query length
* HTTPS usage
* Presence of an IP address
* Number of dots
* Number of hyphens
* Number of slashes
* Number of digits
* Number of letters
* Special characters
* Presence of `@`
* Presence of query parameters
* Number of subdomains
* Punycode detection
* Suspicious keyword count
* Suspicious TLD detection
* Encoded character count
* URL entropy
* Fragment detection
* Underscores
* Parentheses

### Model Performance

The final Random Forest model achieved approximately:

**99.53% accuracy on the held-out test split of the PhiUSIIL dataset.**

> This accuracy refers to the project's dataset test split and should not be interpreted as guaranteed accuracy on arbitrary URLs found on the internet.

---

## 🛡️ Threat Scoring

PhishGuard does not rely only on the raw ML prediction.

The final threat score combines:

```text
Machine Learning Signal
          +
URL Security Indicators
          +
Domain Context
          ↓
Final Threat Score
```

The system considers indicators such as:

* Missing HTTPS
* IP-based URLs
* Suspicious keywords
* Excessive subdomains
* Punycode
* Suspicious top-level domains
* Encoded characters
* Suspicious URL structure
* Excessive URL length
* High URL entropy

The final score is converted into four risk levels:

|  Score | Risk Level |
| -----: | ---------- |
|   0–34 | Low        |
|  35–64 | Medium     |
|  65–84 | High       |
| 85–100 | Critical   |

---

## 🖥️ Screenshots

### Homepage

### Safe URL Detection

### Phishing URL Detection

### Technical URL Analysis

### System Architecture

---

## 🧰 Technology Stack

### Frontend

* HTML
* CSS
* JavaScript
* React
* Vite
* React Hooks

### Backend

* Python
* Flask
* Flask-CORS
* REST API

### Machine Learning

* Scikit-learn
* Random Forest
* Pandas
* NumPy

### Deployment

* Vercel — Frontend
* Render — Backend

### Development Tools

* VS Code
* Git
* GitHub

---

## 📁 Project Structure

```text
phishing-detection/
│
├── backend/
│   ├── app.py
│   ├── feature_extractor.py
│   ├── threat_engine.py
│   ├── test_features.py
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── App.css
│   │   └── main.jsx
│   ├── package.json
│   └── vite.config.js
│
├── models/
│   ├── phishing_model.pkl
│   ├── model_features.pkl
│   └── url_text_model.pkl
│
├── screenshots/
│   ├── homepage.png
│   ├── safe-result.png
│   ├── phishing-result.png
│   ├── technical-analysis.png
│   └── architecture.png
│
├── .gitignore
└── README.md
```

---

## ⚙️ Local Setup

### 1. Clone the repository

```bash
git clone https://github.com/bhandarimuskaan17-stack/phishing-detection.git
```

```bash
cd phishing-detection
```

---

### 2. Create a Python virtual environment

```bash
python -m venv venv
```

Activate it on Windows PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
```

---

### 3. Install backend dependencies

```bash
cd backend
```

```bash
pip install -r requirements.txt
```

---

### 4. Start the Flask backend

```bash
python app.py
```

The backend runs locally on:

```text
http://127.0.0.1:5000
```

---

### 5. Start the React frontend

Open another terminal.

Go to the project:

```powershell
cd C:\Users\Muskaan Bhandari\phishing-detection
```

Then:

```powershell
cd frontend
```

Install frontend dependencies:

```powershell
npm install
```

Start the development server:

```powershell
npm run dev
```

The frontend will be available at the Vite URL shown in the terminal, normally:

```text
http://localhost:5173
```

---

## 🔌 API

### Check URL

**Endpoint**

```text
POST /check-url
```

### Request

```json
{
  "url": "https://example.com"
}
```

### Response

The API returns information including:

* URL
* Result
* Threat score
* Risk level
* Phishing probability
* Legitimate probability
* Detection reasons
* Security indicators
* Recommendation
* Extracted URL features

---

## 🔐 Example Detection

### Likely Safe

```text
https://google.com
```

The system identifies the URL as a low-risk trusted domain.

### Highly Suspicious

```text
http://secure-login-verify-account.com/login?password=confirm
```

The URL contains multiple suspicious characteristics and is expected to receive a **Critical** threat assessment.

---

## 📚 Dataset

The machine-learning model was trained using the **PhiUSIIL Phishing URL Dataset**.

The dataset provides labelled URLs that are used to train and evaluate the phishing classification model.

---

## ⚠️ Disclaimer

PhishGuard is an educational and demonstration project.

A URL being classified as "Likely Safe" does **not guarantee that the website is completely safe**. Similarly, a suspicious score indicates potential risk rather than proving malicious intent.

Users should avoid entering passwords, payment information, or other sensitive information into suspicious websites.

---

## 👩‍💻 Built With

**React + Flask + Machine Learning**

Built as a cybersecurity and web-development project demonstrating:

* Frontend development
* React components and Hooks
* REST API integration
* Machine learning
* Feature engineering
* Explainable security analysis
* Full-stack deployment


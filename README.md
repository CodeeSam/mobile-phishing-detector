# Mobile-Based Phishing Detection System for Banking Security

An Intelligent Security Intervention system designed to protect mobile banking users from phishing attacks using **XGBoost Machine Learning**. This system analyzes URL structures in real-time to identify malicious links before users provide sensitive credentials.

## Project Highlights
* **High Accuracy:** 97.06% detection rate on the UCI Phishing Dataset.
* **Low Latency:** Average inference time of **15.58 ms**, optimized for mobile user experiences.
* **Algorithm:** Gradient Boosted Decision Trees (XGBoost).
* **Deployment:** Live web interface built with **Streamlit**.

## How it Works
The system extracts 30 features from a submitted URL, categorizing them into:
1. **Address Bar Features:** IP addresses, URL length, and shortening services.
2. **Abnormal Features:** Redirecting symbols (`//`) and prefix/suffix hyphens.
3. **Security Markers:** HTTPS/SSL presence and subdirectory depth.

## Tech Stack
* **Language:** Python 3.12
* **ML Library:** XGBoost, Scikit-Learn
* **Interface:** Streamlit
* **Environment:** Anaconda / Virtualenv

## Installation & Local Deployment

1. **Clone the repository:**
   ```bash
   git clone https://github.com/CodeeSam/mobile-phishing-detector.git

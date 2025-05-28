# 🛡️ AI-Based Web Application Firewall (AI-WAF)

A Web Application Firewall (WAF) that combines **pattern-based detection** and **machine learning (Random Forest)** to protect web applications from common attacks such as **SQL Injection (SQLi)** and **Cross-Site Scripting (XSS)**.



##  Overview

This project is a prototype WAF developed in Python using the Flask framework. It:
- Detects suspicious input using regex for SQLi and XSS
- Uses a Random Forest model to identify anomalous inputs
- Logs all requests and displays them on a real-time dashboard
- Allows exporting logs for further analysis



##  Objectives

- Detect known attacks using signature patterns
- Use ML to classify unknown/suspicious inputs
- Log and categorize allowed and blocked requests
- Display analytics in a web-based dashboard
- Provide exportable logs in JSON and TXT format



##  Features

-  Pattern-based and AI-based detection
-  Dashboard with:
  - Visual charts
  - Filters by attack type and status
  - Separate views for allowed and blocked requests
-  Export logs to JSON or TXT
-  Test interface for trying out attacks
- Uses CSIC 2010 HTTP Dataset for training



##  Tech Stack

| Category       | Technology               |
|----------------|--------------------------|
| Backend        | Python, Flask            |
| Machine Learning | scikit-learn (Random Forest) |
| Frontend       | HTML, Bootstrap, CSS     |
| Charts         | Chart.js                 |
| Data           | CSIC 2010 HTTP Dataset   |



##  Project Structure
WAF PROJECT/
│
├── data/
│ └── csic_database.csv # Dataset for model training
│
├── model/
│ ├── training.py # ML model training script
│ └── waf_model.pkl # Trained Random Forest model
│
├── static/
│ ├── shield.webp # Dashboard image asset
│ └── style.css # Custom styles
│
├── templates/
│ ├── attack_analysis.html # Chart dashboard
│ ├── attacks.html # Blocked requests
│ ├── base.html # Layout template
│ ├── dashboard.html # Request log overview
│ ├── index.html # Homepage
│ └── requests.html # Allowed requests
│
├── waf_module/
│ ├── init.py # Module init
│ ├── waf.py # WAF detection logic
│ ├── fix_logs.py # Log format fixer
│ ├── logs.json # Combined logs
│ ├── logs.json.txt # Text format log
│
├── app.py # Main Flask app
├── requirements.txt # Project dependencies
├── Readme.md # This file
├── waf_logs.json # Full log (JSON)
└── waf_logs.txt # Full log (TXT)




##  How to Run

 1. Setup Environment


# Clone the repository
git clone https://github.com/Hiranyaa04/Web-Application-Firewall-With-AI-Anomaly-Detection.git
cd ai-waf

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

pip install Flask-Mail


 2. Configure Email Alerts
To enable email alerts when an attack is detected:

In app.py, update these lines with your own Gmail:

app.config['MAIL_USERNAME'] = 'your_email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your_app_password'  # Generate from Google
app.config['MAIL_DEFAULT_SENDER'] = 'your_email@gmail.com'
 Use an App Password generated from Google Account Settings if 2FA is enabled.


 3. Run the App

python app.py
Then visit:
http://127.0.0.1:5000/
Use the UI to test input detection and view logs.



## Testing the WAF
You can test the WAF with these inputs on the homepage:

SQL Injection:
' OR 1=1 --

XSS Attack:
<script>alert('XSS')</script>

Anomalous Input: 
@@!!9999999999DROP TABLE users

They will be either blocked or allowed, and you can view the result in the dashboard.


## Dataset & Model
Dataset: data/csic_database.csv (based on the CSIC 2010 HTTP dataset)

Features extracted: input length, digit count, special characters, etc.

Model: Trained Random Forest model (model/waf_model.pkl)

Train your own model by running:
python model/training.py


## Logs & Export
Logs are stored in:
waf_module/logs.json
waf_logs.json, waf_logs.txt
You can view them via the dashboard or export for offline analysis.


## Limitations & Future Work
Current AI model may have some false positives
No admin authentication or alerting (yet)

Future ideas:
SMS alerts
IP blacklisting
Live traffic replay or simulation
Model accuracy improvements


## Author
R.K.H. Oshadee Kosgollage
Final Year Student, BSc(hons) Computer Security
NSBM Green University | Plymouth University
Supervised by: Dr. Pabudi Abeyrathne


## License
This project is developed for academic purposes.

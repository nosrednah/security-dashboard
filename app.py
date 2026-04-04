from flask import Flask, render_template, request, jsonify
import requests
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/check-email', methods=['POST'])
def check_email():
    data = request.get_json()
    email = data['email']
    
    url = "https://breachdirectory.p.rapidapi.com/"
    headers = {
        "X-RapidAPI-Key": os.getenv("RAPIDAPI_KEY"),
        "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com"
    }
    params = {"func": "auto", "term": email}
    
    response = requests.get(url, headers=headers, params=params)
    result = response.json()
    
    if result.get("success") and result.get("found") > 0:
        return jsonify({'message': f'⚠️ Breach found! Your email appeared in {result["found"]} breach(es).'})
    else:
        return jsonify({'message': '✅ Good news! No breaches found for this email.'})
    
@app.route('/check-password', methods=['POST'])
def check_password():
    data = request.get_json()
    password = data['password']
    
    score = 0
    feedback = []
    
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("At least 8 characters")
    
    if any(char.isupper() for char in password):
        score += 1
    else:
        feedback.append("Add uppercase letters")
        
    if any(char.islower() for char in password):
        score += 1
    else:
        feedback.append("Add lowercase letters")
        
    if any(char.isdigit() for char in password):
        score += 1
    else:
        feedback.append("Add numbers")
        
    if any(char in '!@#$%^&*()_+-=[]{}|;:,.<>?' for char in password):
        score += 1
    else:
        feedback.append("Add special characters")
    
    if score <= 2:
        strength = "Weak"
    elif score == 3:
        strength = "Medium"
    elif score == 4:
        strength = "Strong"
    else:
        strength = "Very Strong"
    
    return jsonify({'strength': strength, 'score': score, 'feedback': feedback})


if __name__ == '__main__':
    app.run(debug=True)


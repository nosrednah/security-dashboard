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

if __name__ == '__main__':
    app.run(debug=True)
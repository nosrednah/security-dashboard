from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/check-email', methods=['POST'])
def check_email():
    data = request.get_json()
    email = data['email']
    return jsonify({'message': f'Checking email: {email}'})

if __name__ == '__main__':
    app.run(debug=True)
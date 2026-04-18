# Security Dashboard

A dark-themed web dashboard with three cybersecurity tools built with Python Flask.

**Live Demo:** *(add your Render URL here)*

---

## Features

### Email Breach Checker
Enter an email address to check if it has appeared in known data breaches. Powered by the [BreachDirectory API](https://rapidapi.com/rohan-patra/api/breachdirectory).

### Password Strength Analyzer
Analyzes a password in real time and scores it across five criteria — length, uppercase, lowercase, numbers, and special characters. Returns a strength rating (Weak / Medium / Strong / Very Strong) with a color-coded progress bar.

### URL Safety Checker
Checks a URL against Google's Safe Browsing database to detect malware, phishing, and unwanted software.

---

## Screenshots

> *(Add screenshots here after deployment)*

---

## Tech Stack

- **Backend:** Python, Flask, Gunicorn
- **Frontend:** Vanilla HTML, CSS, JavaScript
- **APIs:** BreachDirectory (RapidAPI), Google Safe Browsing
- **Config:** python-dotenv

---

## Local Setup

1. Clone the repo:
   ```bash
   git clone https://github.com/nosrednah/security-dashboard.git
   cd security-dashboard
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Create a `.env` file in the project root:
   ```
   RAPIDAPI_KEY=your_rapidapi_key_here
   GOOGLE_API_KEY=your_google_api_key_here
   ```

4. Run the app:
   ```bash
   python app.py
   ```

5. Open [http://localhost:5000](http://localhost:5000)

---

## Deployment (Render.com)

1. Push this repo to GitHub
2. Go to [render.com](https://render.com) → New → Web Service
3. Connect your GitHub repo
4. Add environment variables in the Render dashboard:
   - `RAPIDAPI_KEY`
   - `GOOGLE_API_KEY`
5. Deploy — Render uses the included `Procfile` and `render.yaml` automatically

---

## Environment Variables

| Variable | Description |
|---|---|
| `RAPIDAPI_KEY` | API key from RapidAPI for BreachDirectory |
| `GOOGLE_API_KEY` | Google Cloud API key with Safe Browsing enabled |

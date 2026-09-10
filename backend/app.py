from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib

from feature_extractor import extract_features
from threat_engine import calculate_threat_score


app = Flask(__name__)
CORS(app)


# --------------------------------------------------
# Load URL-text ML model
# --------------------------------------------------

model = joblib.load("../models/url_text_model.pkl")


# --------------------------------------------------
# Home route
# --------------------------------------------------

@app.route("/")
def home():

    return jsonify({
        "message": "PhishGuard Threat Detection API is running!"
    })


# --------------------------------------------------
# URL scanning route
# --------------------------------------------------

@app.route("/check-url", methods=["POST"])
def check_url():

    data = request.get_json()

    # --------------------------------------------------
    # Check request
    # --------------------------------------------------

    if not data:

        return jsonify({
            "error": "No data received."
        }), 400

    url = data.get("url", "").strip()

    if not url:

        return jsonify({
            "error": "URL is required."
        }), 400

    try:

        # --------------------------------------------------
        # 1. Extract security features
        # --------------------------------------------------

        features = extract_features(url)


        # --------------------------------------------------
        # 2. ML prediction
        # --------------------------------------------------

        prediction = model.predict([url])[0]

        probabilities = model.predict_proba([url])[0]


        # Dataset convention:
        #
        # 0 = Phishing
        # 1 = Legitimate
        #

        phishing_probability = float(
            probabilities[0]
        )

        legitimate_probability = float(
            probabilities[1]
        )


        # --------------------------------------------------
        # 3. Hybrid threat engine
        # --------------------------------------------------

        threat_result = calculate_threat_score(
            url,
            features,
            phishing_probability
        )


        # --------------------------------------------------
        # 4. Final result
        # --------------------------------------------------

        threat_score = threat_result["threat_score"]

        risk_level = threat_result["risk_level"]

        reasons = threat_result["reasons"]

        indicators = threat_result["indicators"]


        if threat_score >= 65:

            result = "Potentially Dangerous"

        else:

            result = "Likely Safe"


        # --------------------------------------------------
        # 5. Recommendation
        # --------------------------------------------------

        if risk_level == "Critical":

            recommendation = (
                "Avoid visiting this URL. "
                "It shows multiple high-risk indicators."
            )

        elif risk_level == "High":

            recommendation = (
                "Proceed with extreme caution. "
                "Do not enter passwords or sensitive information."
            )

        elif risk_level == "Medium":

            recommendation = (
                "Be cautious before interacting with this website."
            )

        else:

            recommendation = (
                "No major threats were detected from the URL structure."
            )


        # --------------------------------------------------
        # 6. Return security report
        # --------------------------------------------------

        return jsonify({

            "url": url,

            "result": result,

            "threat_score": threat_score,

            "risk_level": risk_level,

            "phishing_probability": round(
                phishing_probability,
                4
            ),

            "legitimate_probability": round(
                legitimate_probability,
                4
            ),

            "reasons": reasons,

            "indicators": indicators,

            "recommendation": recommendation,

            "features": features

        })


    except Exception as e:

        print("ERROR:", str(e))

        return jsonify({
            "error": str(e)
        }), 500


# --------------------------------------------------
# Run server
# --------------------------------------------------

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
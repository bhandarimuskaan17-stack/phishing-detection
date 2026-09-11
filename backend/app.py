
from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import os

from feature_extractor import (
    extract_features,
    normalize_url
)

from threat_engine import (
    calculate_threat_score
)


app = Flask(__name__)

CORS(app)


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

MODEL_PATH = os.path.join(
    BASE_DIR,
    "..",
    "models",
    "url_text_model.pkl"
)


# ============================================================
# LOAD ML MODEL
# ============================================================

try:

    model = joblib.load(
        MODEL_PATH
    )

    print(
        "Phishing ML model loaded successfully."
    )

except Exception as e:

    print(
        "ERROR loading ML model:",
        str(e)
    )

    model = None


# ============================================================
# HOME ROUTE
# ============================================================

@app.route("/")
def home():

    return jsonify({

        "message":
            "PhishGuard Threat Detection API is running!",

        "status":
            "online"

    })


# ============================================================
# URL SCANNER
# ============================================================

@app.route(
    "/check-url",
    methods=["POST"]
)
def check_url():

    data = request.get_json(
        silent=True
    )

    # --------------------------------------------------
    # REQUEST VALIDATION
    # --------------------------------------------------

    if not data:

        return jsonify({

            "error":
                "No data received."

        }), 400


    raw_url = data.get(
        "url",
        ""
    )


    if not isinstance(
        raw_url,
        str
    ):

        return jsonify({

            "error":
                "URL must be a text value."

        }), 400


    raw_url = raw_url.strip()


    if not raw_url:

        return jsonify({

            "error":
                "URL is required."

        }), 400


    # --------------------------------------------------
    # NORMALIZE URL
    # --------------------------------------------------

    url = normalize_url(
        raw_url
    )


    # --------------------------------------------------
    # BASIC URL VALIDATION
    # --------------------------------------------------

    if not url.startswith(
        ("http://", "https://")
    ):

        return jsonify({

            "error":
                "Please enter a valid website address."

        }), 400


    try:

        # ==================================================
        # 1. FEATURE EXTRACTION
        # ==================================================

        features = extract_features(
            url
        )


        # ==================================================
        # 2. ML ANALYSIS
        # ==================================================

        if model is not None:

            probabilities = model.predict_proba(
                [url]
            )[0]


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

        else:

            phishing_probability = 0.0

            legitimate_probability = 1.0


        # ==================================================
        # 3. HYBRID THREAT ENGINE
        # ==================================================

        threat_result = calculate_threat_score(

            url,

            features,

            phishing_probability
        )


        threat_score = threat_result[
            "threat_score"
        ]

        risk_level = threat_result[
            "risk_level"
        ]

        reasons = threat_result[
            "reasons"
        ]

        indicators = threat_result[
            "indicators"
        ]


        # ==================================================
        # 4. FINAL RESULT
        # ==================================================

        if risk_level in (
            "Critical",
            "High"
        ):

            result = (
                "Potentially Dangerous"
            )

        else:

            result = (
                "Likely Safe"
            )


        # ==================================================
        # 5. RECOMMENDATION
        # ==================================================

        if risk_level == "Critical":

            recommendation = (
                "Avoid visiting this URL. "
                "Multiple strong indicators suggest "
                "that it may be unsafe."
            )

        elif risk_level == "High":

            recommendation = (
                "Proceed with extreme caution. "
                "Avoid entering passwords or sensitive "
                "information unless the website is verified."
            )

        elif risk_level == "Medium":

            recommendation = (
                "Be cautious before interacting with "
                "this website and verify the destination."
            )

        else:

            recommendation = (
                "No major threats were detected from "
                "the URL structure."
            )


        # ==================================================
        # 6. RETURN SECURITY REPORT
        # ==================================================

        return jsonify({

            "url": url,

            "result": result,

            "threat_score": threat_score,

            "risk_level": risk_level,

            "phishing_probability":
                round(
                    phishing_probability,
                    4
                ),

            "legitimate_probability":
                round(
                    legitimate_probability,
                    4
                ),

            "reasons": reasons,

            "indicators": indicators,

            "recommendation":
                recommendation,

            "features":
                features

        })


    except Exception as e:

        print(
            "ERROR:",
            str(e)
        )

        return jsonify({

            "error":
                "Unable to analyze this URL."

        }), 500


# ============================================================
# LOCAL DEVELOPMENT
# ============================================================

if __name__ == "__main__":

    app.run(

        host="127.0.0.1",

        port=5000,

        debug=True
    )


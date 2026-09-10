import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
from sklearn.pipeline import Pipeline


# --------------------------------------------------
# 1. Load dataset
# --------------------------------------------------

DATA_PATH = "data/PhiUSIIL_Phishing_URL_Dataset.csv"

print("Loading dataset...")

df = pd.read_csv(DATA_PATH)

print("Dataset loaded:", df.shape)


# --------------------------------------------------
# 2. Get URLs and labels
# --------------------------------------------------

X = df["URL"].astype(str)
y = df["label"]

print("\nLabels:")
print(y.value_counts())


# --------------------------------------------------
# 3. Train-test split
# --------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("\nTraining samples:", len(X_train))
print("Testing samples:", len(X_test))


# --------------------------------------------------
# 4. Create URL text model
# --------------------------------------------------

print("\nTraining URL pattern model...")

model = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            analyzer="char",
            ngram_range=(2, 5),
            min_df=2,
            max_features=100000,
            sublinear_tf=True
        )
    ),
    (
        "classifier",
        LogisticRegression(
            max_iter=1000,
            class_weight="balanced"
        )
    )
])


# --------------------------------------------------
# 5. Train
# --------------------------------------------------

model.fit(X_train, y_train)


# --------------------------------------------------
# 6. Evaluate
# --------------------------------------------------

print("\nEvaluating model...")

predictions = model.predict(X_test)

accuracy = accuracy_score(
    y_test,
    predictions
)

print("\nAccuracy:")
print(f"{accuracy * 100:.2f}%")


print("\nClassification Report:")

print(
    classification_report(
        y_test,
        predictions
    )
)


# --------------------------------------------------
# 7. Test Google immediately
# --------------------------------------------------

test_urls = [
    "https://google.com",
    "https://www.youtube.com",
    "https://www.amazon.in",
    "http://192.168.1.1/login",
    "http://secure-login-verify-account.example.com"
]

print("\nReal-world test:")

for url in test_urls:

    prediction = model.predict([url])[0]

    probability = model.predict_proba([url])[0]

    phishing_probability = probability[0]
    legitimate_probability = probability[1]

    if prediction == 0:
        result = "Phishing"
    else:
        result = "Legitimate"

    print("\nURL:", url)
    print("Result:", result)
    print(
        "Phishing probability:",
        round(phishing_probability * 100, 2),
        "%"
    )
    print(
        "Legitimate probability:",
        round(legitimate_probability * 100, 2),
        "%"
    )


# --------------------------------------------------
# 8. Save model
# --------------------------------------------------

MODEL_PATH = "models/url_text_model.pkl"

joblib.dump(
    model,
    MODEL_PATH
)

print("\nNew URL model saved successfully!")

print(MODEL_PATH)
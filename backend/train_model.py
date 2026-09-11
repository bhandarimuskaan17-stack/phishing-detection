
import os
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

from feature_extractor import extract_features


# --------------------------------------------------
# 1. Paths
# --------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATA_PATH = os.path.join(
    BASE_DIR,
    "..",
    "data",
    "PhiUSIIL_Phishing_URL_Dataset.csv"
)

MODEL_DIR = os.path.join(
    BASE_DIR,
    "..",
    "models"
)

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "phishing_model.pkl"
)


# --------------------------------------------------
# 2. Load dataset
# --------------------------------------------------

print("Loading dataset...")

df = pd.read_csv(DATA_PATH)

print("Dataset loaded successfully.")
print("Dataset shape:", df.shape)


# --------------------------------------------------
# 3. Basic dataset validation
# --------------------------------------------------

print("\nChecking dataset...")

print("Missing URLs:", df["URL"].isna().sum())
print("Missing labels:", df["label"].isna().sum())

# Remove rows where URL or label is missing.
df = df.dropna(
    subset=["URL", "label"]
).copy()

print("Dataset after cleaning:", df.shape)


# --------------------------------------------------
# 4. Select URL and label
# --------------------------------------------------

X_urls = df["URL"].astype(str)
y = df["label"]


# --------------------------------------------------
# 5. Extract features from URLs
# --------------------------------------------------

print("\nExtracting URL features...")

feature_rows = []

for i, url in enumerate(X_urls):

    features = extract_features(url)

    feature_rows.append(features)

    if (i + 1) % 10000 == 0:
        print(f"Processed {i + 1} URLs")


X = pd.DataFrame(feature_rows)


# --------------------------------------------------
# 6. Remove non-numeric / identifier columns
# --------------------------------------------------

# hostname is useful for the threat engine, but it must
# NOT be given directly to Random Forest because it is text.
#
# Example:
# "google.com"
# "facebook.com"
# "amazon.in"
#
# Training on raw hostnames could also allow the model
# to memorize individual domains rather than learning
# general URL-security patterns.

if "hostname" in X.columns:
    X = X.drop(columns=["hostname"])


# --------------------------------------------------
# 7. Make sure every ML feature is numeric
# --------------------------------------------------

print("\nConverting features to numeric values...")

X = X.apply(
    pd.to_numeric,
    errors="coerce"
)

# Replace any unexpected conversion failures with 0.
X = X.fillna(0)


# --------------------------------------------------
# 8. Display features
# --------------------------------------------------

print("\nFeature extraction completed.")

print("Number of features:", len(X.columns))

print("\nFeatures used:")

for feature in X.columns:
    print("-", feature)


# --------------------------------------------------
# 9. Verify that every feature is numeric
# --------------------------------------------------

non_numeric_columns = X.select_dtypes(
    exclude=["number"]
).columns.tolist()

if non_numeric_columns:

    raise ValueError(
        f"Non-numeric features still exist: {non_numeric_columns}"
    )

print("\nAll training features are numeric.")


# --------------------------------------------------
# 10. Training labels
# --------------------------------------------------

print("\nTraining labels:")

print(
    y.value_counts()
)


# --------------------------------------------------
# 11. Train-test split
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
# 12. Train Random Forest
# --------------------------------------------------

print("\nTraining Random Forest model...")

model = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)

model.fit(
    X_train,
    y_train
)


# --------------------------------------------------
# 13. Evaluate model
# --------------------------------------------------

print("\nEvaluating model...")

predictions = model.predict(
    X_test
)

accuracy = accuracy_score(
    y_test,
    predictions
)

print("\nModel Accuracy:")
print(
    f"{accuracy * 100:.2f}%"
)

print("\nClassification Report:")

print(
    classification_report(
        y_test,
        predictions
    )
)


# --------------------------------------------------
# 14. Feature importance
# --------------------------------------------------

print("\nTop feature importances:")

importances = pd.Series(
    model.feature_importances_,
    index=X.columns
).sort_values(
    ascending=False
)

print(
    importances.head(10)
)


# --------------------------------------------------
# 15. Save model
# --------------------------------------------------

os.makedirs(
    MODEL_DIR,
    exist_ok=True
)

joblib.dump(
    model,
    MODEL_PATH
)


print("\nModel saved successfully!")

print("Saved to:")
print(MODEL_PATH)


# --------------------------------------------------
# 16. Save feature order
# --------------------------------------------------

FEATURE_ORDER_PATH = os.path.join(
    MODEL_DIR,
    "model_features.pkl"
)

joblib.dump(
    list(X.columns),
    FEATURE_ORDER_PATH
)

print("\nFeature order saved to:")
print(FEATURE_ORDER_PATH)


# --------------------------------------------------
# 17. Final model information
# --------------------------------------------------

print("\nFinal model information:")

print(
    "Number of features expected by model:",
    len(model.feature_names_in_)
)

print(
    "Feature order:"
)

print(
    list(model.feature_names_in_)
)


import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

from feature_extractor import extract_features


# Load dataset
df = pd.read_csv("../data/PhiUSIIL_Phishing_URL_Dataset.csv")

print("Dataset loaded:", df.shape)


# Extract our URL-based features
X = df["URL"].apply(extract_features).apply(pd.Series)

y = df["label"]


print("\nFeatures used:")
print(X.columns.tolist())

print("\nNumber of features:", X.shape[1])

print("\nTraining labels:")
print(y.value_counts())


# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)


# Create model
model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    class_weight="balanced",
    n_jobs=-1
)


# Train
print("\nTraining model...")
model.fit(X_train, y_train)


# Evaluate
predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

print("\nAccuracy:", accuracy)

print("\nClassification Report:")
print(classification_report(y_test, predictions))


# Save model
joblib.dump(model, "../models/phishing_model.pkl")

print("\nNew model saved successfully!")
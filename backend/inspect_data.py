import pandas as pd

file_path = "../data/PhiUSIIL_Phishing_URL_Dataset.csv"

df = pd.read_csv(file_path)

print("Dataset shape:")
print(df.shape)

print("\nColumns:")
print(df.columns.tolist())

print("\nFirst 5 rows:")
print(df.head())

print("\nLabel counts:")
print(df["label"].value_counts())
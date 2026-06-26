import json
from pathlib import Path

import joblib
import lightgbm as lgb
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

DATASET_PATH = "final_static_dataset.csv"
MODEL_PATH = "lgbm_static_model_v3.pkl"
METADATA_PATH = "lgbm_static_model_v3.metadata.json"
TARGET = "class"


def normalize_contains_text(value):
    value = str(value).strip().lower()
    mapping = {
        "true": 1,
        "false": 0,
        "yes": 1,
        "no": 0,
        "1": 1,
        "0": 0,
    }
    return mapping.get(value, 0)


def load_and_clean(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)

    if "name" in df.columns:
        df = df.drop(columns=["name"])

    if "contains_text" in df.columns:
        df["contains_text"] = df["contains_text"].apply(normalize_contains_text)

    if "header" in df.columns:
        df["header"] = (
            df["header"].astype(str).str.extract(r"(\d+\.\d+)")[0].fillna("0").astype(float)
        )

    df[TARGET] = df[TARGET].astype(str).str.strip().str.lower().map({"benign": 0, "malicious": 1})
    df = df.dropna(subset=[TARGET]).copy()

    # Ensure numeric columns only after explicit normalization.
    feature_columns = [c for c in df.columns if c != TARGET]
    for col in feature_columns:
        if df[col].dtype == "object":
            df[col] = pd.to_numeric(df[col], errors="coerce")

    df = df.fillna(0)
    return df


def main():
    df = load_and_clean(DATASET_PATH)
    X = df.drop(columns=[TARGET])
    y = df[TARGET].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
        shuffle=True,
    )

    model = lgb.LGBMClassifier(
        objective="binary",
        n_estimators=1500,
        learning_rate=0.03,
        num_leaves=31,
        subsample=0.9,
        colsample_bytree=0.9,
        random_state=42,
        class_weight="balanced",
        verbose=-1,
    )

    model.fit(
        X_train,
        y_train,
        eval_set=[(X_test, y_test)],
        eval_metric="binary_logloss",
        callbacks=[lgb.early_stopping(stopping_rounds=100)],
    )

    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred, output_dict=True)
    cm = confusion_matrix(y_test, y_pred).tolist()

    joblib.dump(model, MODEL_PATH)

    metadata = {
        "dataset_path": DATASET_PATH,
        "model_path": MODEL_PATH,
        "feature_names": list(X.columns),
        "accuracy": accuracy,
        "classification_report": report,
        "confusion_matrix": cm,
        "train_rows": int(len(X_train)),
        "test_rows": int(len(X_test)),
    }

    Path(METADATA_PATH).write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    print(f"Saved model -> {MODEL_PATH}")
    print(f"Saved metadata -> {METADATA_PATH}")
    print(f"Accuracy: {accuracy:.4f}")


if __name__ == "__main__":
    main()

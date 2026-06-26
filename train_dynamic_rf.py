import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

DATASET_PATH = r"C:\pdf_sandbox\shared\features\dynamic_dataset_rebuilt_full.csv"
MODEL_PATH = r"C:\pdf_sandbox\shared\features\rf_dynamic_model.pkl"
METADATA_PATH = r"C:\pdf_sandbox\shared\features\rf_dynamic_model_metadata.json"

TARGET = "label"
DROP_COLUMNS = ["sha256", "date"]


def main():
    df = pd.read_csv(DATASET_PATH)

    required = [TARGET] + DROP_COLUMNS
    for col in required:
        if col not in df.columns:
            raise ValueError(f"Required column missing: {col}")

    if df.isna().sum().sum() > 0:
        raise ValueError("Dataset contains missing values. Clean it first.")

    X = df.drop(columns=[TARGET] + DROP_COLUMNS)
    y = df[TARGET].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
        shuffle=True,
    )

    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        min_samples_split=2,
        min_samples_leaf=1,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
    )

    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred, output_dict=True)
    cm = confusion_matrix(y_test, y_pred).tolist()

    importances = (
        pd.DataFrame({
            "feature": X.columns,
            "importance": model.feature_importances_
        })
        .sort_values("importance", ascending=False)
        .reset_index(drop=True)
    )

    joblib.dump(model, MODEL_PATH)

    metadata = {
        "dataset_path": DATASET_PATH,
        "model_path": MODEL_PATH,
        "target": TARGET,
        "dropped_columns": DROP_COLUMNS,
        "feature_names": list(X.columns),
        "accuracy": accuracy,
        "classification_report": report,
        "confusion_matrix": cm,
        "train_rows": int(len(X_train)),
        "test_rows": int(len(X_test)),
        "top_10_features": importances.head(10).to_dict(orient="records"),
    }

    Path(METADATA_PATH).write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    print(f"Saved model -> {MODEL_PATH}")
    print(f"Saved metadata -> {METADATA_PATH}")
    print(f"Accuracy: {accuracy:.4f}")
    print("\nTop 10 features:")
    print(importances.head(10).to_string(index=False))


if __name__ == "__main__":
    main()
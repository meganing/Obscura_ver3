import pandas as pd
import hashlib

def anonymize_file(input_path, output_path=None, payload=None, preview_only=False):
    df = pd.read_excel(input_path) if input_path.endswith(".xlsx") else pd.read_csv(input_path)

    headers = list(df.columns)
    preview_data = df.head(5).to_dict(orient="records")

    # Simple PII demo: detect fields containing 'name', 'email', 'phone'
    detected = {}
    for col in headers:
        lowered = col.lower()
        if any(tag in lowered for tag in ["name", "email", "phone"]):
            detected[col] = "Potential PII"

    if preview_only:
        return preview_data, headers, detected

    if payload:
        selected_cols = payload.get("selected_pii", [])
        techniques = payload.get("techniques", {})

        for col in selected_cols:
            if col in df.columns:
                if techniques.get("masking"):
                    df[col] = df[col].astype(str).apply(lambda x: x[0] + "***" if x else "")
                elif techniques.get("hashing"):
                    df[col] = df[col].astype(str).apply(lambda x: hashlib.sha256(x.encode()).hexdigest())

    if output_path:
        if output_path.endswith(".xlsx"):
            df.to_excel(output_path, index=False)
        else:
            df.to_csv(output_path, index=False)

    return None
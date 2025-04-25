import pandas as pd
import hashlib
from typing import Optional, Dict, List, Tuple, Any

def anonymize_file(
    input_path: str,
    output_path: Optional[str] = None,
    payload: Optional[Dict[str, Any]] = None,
    preview_only: bool = False
) -> Optional[Tuple[List[Dict[str, Any]], List[str], Dict[str, str]]]:
    """
    Reads a CSV or Excel file, detects potential PII in headers,
    and optionally anonymizes selected columns using masking or hashing.

    Args:
        input_path: Path to the input file (.csv or .xlsx).
        output_path: Path to save the anonymized file. Required if not preview_only.
        payload: Dictionary containing 'selected_pii' (list of columns)
                 and 'techniques' (dict like {'masking': bool, 'hashing': bool}).
                 Required if not preview_only.
        preview_only: If True, returns preview data, headers, and detected PII
                      without modifying or saving the file.

    Returns:
        If preview_only is True, returns a tuple:
        (preview_data, headers, detected_pii).
        Otherwise, returns None after saving the file.

    Raises:
        ValueError: If file format is unsupported.
        FileNotFoundError: If input_path does not exist.
    """
    try:
        if input_path.endswith(".xlsx"):
            df = pd.read_excel(input_path)
        elif input_path.endswith(".csv"):
            df = pd.read_csv(input_path)
        else:
            raise ValueError(f"Unsupported file type for input: {input_path}")
    except FileNotFoundError:
        raise FileNotFoundError(f"Input file not found: {input_path}")

    headers = list(df.columns)
    # Ensure preview data handles potential non-string types gracefully for JSON serialization
    preview_data = df.head(5).astype(object).where(pd.notnull(df.head(5)), None).to_dict(orient="records")


    # Simple PII demo: detect fields containing 'name', 'email', 'phone' in headers (case-insensitive)
    detected: Dict[str, str] = {}
    pii_keywords = ["name", "email", "phone", "address", "ssn", "social security", "credit card"] # Added more keywords
    for col in headers:
        lowered = col.lower()
        if any(tag in lowered for tag in pii_keywords):
            detected[col] = "Potential PII (Header Match)" # More specific reason

    if preview_only:
        return preview_data, headers, detected

    # Anonymization logic requires payload and output_path
    if not payload:
        raise ValueError("Payload with selected PII and techniques is required for anonymization.")
    if not output_path:
        raise ValueError("Output path is required for anonymization.")

    selected_cols = payload.get("selected_pii", [])
    techniques = payload.get("techniques", {})

    # --- Anonymization Technique Application ---
    # Note: Masking takes priority if both masking and hashing are selected.
    for col in selected_cols:
        if col in df.columns:
            # Convert column to string type for consistent processing, handle NaN/None
            df[col] = df[col].astype(str).replace('nan', '').replace('None', '')

            if techniques.get("masking"):
                # Mask all but the first character. Handle empty strings.
                df[col] = df[col].apply(lambda x: (x[0] + '***' + x[-1] if len(x) > 1 else x[0] + '***') if x else '')
            elif techniques.get("hashing"):
                # Apply SHA256 hashing
                df[col] = df[col].apply(lambda x: hashlib.sha256(x.encode('utf-8')).hexdigest() if x else '')

    # --- Saving the anonymized file ---
    try:
        if output_path.endswith(".xlsx"):
            df.to_excel(output_path, index=False)
        elif output_path.endswith(".csv"):
            df.to_csv(output_path, index=False)
        else:
             raise ValueError(f"Unsupported file type for output: {output_path}")

    except Exception as e:
        # Handle potential errors during file writing (e.g., permissions)
        print(f"Error saving anonymized file to {output_path}: {e}") # Consider proper logging
        raise

    return None # Explicitly return None when not previewing
import os
import hashlib
import time
import logging # Import logging
from typing import List

# Configure logging (use the same logger as main.py if desired)
log = logging.getLogger("obscura")

def generate_file_hash(path: str) -> str:
    """Generates a SHA256 hash for the contents of a file."""
    hasher = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while chunk := f.read(4096): # Use walrus operator for cleaner loop
                hasher.update(chunk)
    except FileNotFoundError:
        log.error(f"Cannot generate hash: File not found at {path}")
        return "error_file_not_found"
    except Exception as e:
        log.error(f"Error generating hash for {path}: {e}")
        return f"error_hashing_failed:_{e}"
    return hasher.hexdigest()

def cleanup_temp_files(directory: str, max_age_seconds: int = 600) -> List[str]:
    """
    Removes files older than max_age_seconds from the specified directory.

    Args:
        directory: The directory to clean up.
        max_age_seconds: Maximum age of files in seconds to keep.

    Returns:
        A list of files that were successfully removed.
    """
    now = time.time()
    removed_files = []
    if not os.path.isdir(directory):
        log.warning(f"Cleanup directory not found: {directory}")
        return []

    try:
        for filename in os.listdir(directory):
            path = os.path.join(directory, filename)
            try:
                if os.path.isfile(path):
                    file_mtime = os.path.getmtime(path)
                    if now - file_mtime > max_age_seconds:
                        os.remove(path)
                        removed_files.append(path)
                        log.info(f"Cleaned up old temporary file: {path}")
            except FileNotFoundError:
                # File might have been removed by another process between listdir and getmtime/remove
                log.warning(f"File {path} not found during cleanup (possibly already removed).")
                continue
            except OSError as e:
                # Catch permission errors, etc.
                log.error(f"Error removing temporary file {path}: {e}")
            except Exception as e:
                log.error(f"Unexpected error processing file {path} during cleanup: {e}")
    except Exception as e:
        log.error(f"Error listing directory {directory} during cleanup: {e}")

    return removed_files
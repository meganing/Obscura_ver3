# backend/security.py (with DEBUG prints)

from passlib.context import CryptContext
from fastapi import Request, HTTPException, Depends, status
from typing import Dict, Optional
import os # Keep os import even if not used directly in simplified USERS
import logging

# Configure logging
log = logging.getLogger("obscura")

# --- !!! TEMPORARY DEBUGGING VERSION !!! ---
# Using direct hashes to eliminate os.environ.get as a variable
USERS: Dict[str, Dict[str, str]] = {
    "admin": {
        "hashed_password": "$2b$12$XKST7L7C5hPbQkwOBozheOCt/2VwrXhtbXf1RR3IqezSSGQhsd9UO", # Direct hash for admin123
        "role": "admin"
    },
    "user": {
        "hashed_password": "$2b$12$9XxSIVPGhEYK9Py5B53MleovA.L5OW.ydx0.vHeU63v1zhV8EF.6a", # Direct hash for user123
        "role": "user"
    }
}
# --- !!! END TEMPORARY DEBUGGING VERSION !!! ---

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_user(username: str, password: str) -> Optional[Dict[str, str]]:
    """Verifies username and password against stored credentials."""
    user_data = USERS.get(username)
    if not user_data:
        log.warning(f"Login attempt failed: Unknown user '{username}'")
        return None

    stored_hash = user_data.get("hashed_password") # Use .get() for safety

    # --- START DEBUG PRINTS ---
    print(f"\n--- LOGIN DEBUG ---")
    print(f"Username attempting: '{username}'")
    print(f"Password entered (type: {type(password)}, length: {len(password)}): '{password}'")
    print(f"Stored hash found (type: {type(stored_hash)}, length: {len(stored_hash) if stored_hash else 0}): '{stored_hash}'")
    # --- END DEBUG PRINTS ---

    if not stored_hash:
        log.error(f"CRITICAL: No hashed_password found for user '{username}'!")
        print(f"DEBUG: No hash found for user '{username}' in USERS dict!") # Added debug print
        return None # Or raise an exception

    # This is the line where the comparison happens
    verification_result = False # Default to False
    try:
        verification_result = pwd_context.verify(password, stored_hash)
        print(f"DEBUG: pwd_context.verify result: {verification_result}") # Print verify result
    except Exception as e:
        print(f"DEBUG: EXCEPTION during pwd_context.verify: {e}") # Print any exception during verify
        log.error(f"Exception during password verification for user '{username}': {e}")
        # Optionally re-raise or handle differently, but for debug, just printing helps

    print(f"--- END DEBUG ---\n") # Moved end debug marker

    if not verification_result:
        log.warning(f"Login attempt failed: Invalid password for user '{username}' (Verification returned False)") # Added detail
        return None

    log.info(f"User '{username}' successfully authenticated.")
    return {"username": username, "role": user_data["role"]}


# --- Keep the rest of the functions as they were ---

def get_current_user(request: Request) -> Dict[str, str]:
    """Retrieves the current user from the session or raises Unauthorized."""
    user = request.session.get("user")
    if not user:
        log.warning("Unauthorized access attempt: No user in session.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

def require_admin(user: Dict[str, str] = Depends(get_current_user)) -> Dict[str, str]:
    """Dependency to ensure the current user has the 'admin' role."""
    if user.get("role") != "admin":
        log.warning(f"Forbidden access attempt: User '{user.get('username')}' (role: {user.get('role')}) tried to access admin resource.")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return user

# --- End of file ---
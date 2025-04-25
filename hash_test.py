# hash_test.py
from passlib.context import CryptContext

print("--- Starting Hash Test ---")
try:
    # Use the same context settings as your app
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    print("DEBUG: CryptContext created.")

    password_to_hash = "admin123"
    print(f"DEBUG: Hashing password: '{password_to_hash}'")
    new_hash = pwd_context.hash(password_to_hash)
    print(f"Generated Hash: {new_hash}")

    # Verify the hash immediately
    print(f"\nDEBUG: Verifying password '{password_to_hash}' against NEW hash '{new_hash}'...")
    is_valid = pwd_context.verify(password_to_hash, new_hash)
    print(f"Verification Result (new hash): {is_valid}") # Should be True

    # Verify against the known hash from security.py
    known_hash = "$2b$12$9XxSIVPGhEYK9Py5B53MleovA.L5OW.ydx0.vHeU63v1zhV8EF.6a"
    print(f"\nDEBUG: Verifying password '{password_to_hash}' against KNOWN hash '{known_hash}'...")
    is_known_valid = pwd_context.verify(password_to_hash, known_hash)
    print(f"Verification Result (known hash): {is_known_valid}") # <<< This is the key result

    # Verify admin hash too
    admin_password = "admin123"
    admin_known_hash = "$2b$12$XKST7L7C5hPbQkwOBozheOCt/2VwrXhtbXf1RR3IqezSSGQhsd9UO"
    print(f"\nDEBUG: Verifying admin password '{admin_password}' against KNOWN admin hash '{admin_known_hash}'...")
    is_admin_known_valid = pwd_context.verify(admin_password, admin_known_hash)
    print(f"Verification Result (admin known hash): {is_admin_known_valid}") # <<< Also key

except Exception as e:
    print(f"\nERROR during hash test: {e}")
    import traceback
    traceback.print_exc()

print("\n--- Hash Test Complete ---")
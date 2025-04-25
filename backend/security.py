from passlib.context import CryptContext
from fastapi import Request, HTTPException, Depends

USERS = {
    "admin": {
        "hashed_password": "$2b$12$XKST7L7C5hPbQkwOBozheOCt/2VwrXhtbXf1RR3IqezSSGQhsd9UO",  # admin123
        "role": "admin"
    },
    "user": {
        "hashed_password": "$2b$12$9XxSIVPGhEYK9Py5B53MleovA.L5OW.ydx0.vHeU63v1zhV8EF.6a",  # user123
        "role": "user"
    }
}

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_user(username: str, password: str):
    user = USERS.get(username)
    if not user:
        return None
    if not pwd_context.verify(password, user["hashed_password"]):
        return None
    return {"username": username, "role": user["role"]}

def get_current_user(request: Request):
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return user

def require_admin(user=Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    return user
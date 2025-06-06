from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from enum import Enum
from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from jose import JWTError, jwt
from passlib.context import CryptContext

# --- Configuration Constants ---
# IMPORTANT: This is a placeholder secret key.
# MUST be changed for production and kept secret.
# Generate a strong key using: openssl rand -hex 32
SECRET_KEY = "your-secret-key-here-please-change-for-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# --- Password Hashing ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against a hashed password."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Hashes a password using bcrypt."""
    return pwd_context.hash(password)

# --- Pydantic Models ---
class TokenData(BaseModel):
    username: Optional[str] = None
    scopes: List[str] = [] # For role-based access control

class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = False
    roles: List[str] = []

class UserInDB(User):
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str

# --- Placeholder User Database ---
# In a real application, this would be a proper database.
# Note: Storing this directly in code is not secure for production.
_fake_users_db_storage: Dict[str, UserInDB] = {
# --- Roles Enum ---
class UserRoles(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    AGENT = "agent" # Example of a system-level role for programmatic access

# --- Pydantic Models ---
# (TokenData, User, UserInDB, Token remain largely the same, roles field already exists)

# --- Placeholder User Database (Updated with Enum Roles) ---
_fake_users_db_storage: Dict[str, UserInDB] = {
    "admin": UserInDB(
        username="admin",
        email="admin@example.com",
        full_name="Administrator",
        disabled=False,
        roles=[UserRoles.ADMIN, UserRoles.ANALYST],
        hashed_password=get_password_hash("adminpass")
    ),
    "user1": UserInDB(
        username="user1", # Analyst example
        email="user1@example.com",
        full_name="User One (Analyst)",
        disabled=False,
        roles=[UserRoles.ANALYST],
        hashed_password=get_password_hash("user1pass")
    ),
    "agent_user": UserInDB( # New agent user
        username="agent_user",
        email="agent@internal.system",
        full_name="System Agent User",
        disabled=False,
        roles=[UserRoles.AGENT],
        hashed_password=get_password_hash("agentpass") # Secure this appropriately
    ),
    "disabled_user": UserInDB(
        username="disabled_user",
        email="disabled@example.com",
        full_name="Disabled User",
        disabled=True,
        roles=["user"],
        hashed_password=get_password_hash("disabledpass")
    )
}
# This alias is to allow the /token endpoint (if in another file) to import it easily.
# It's better to pass the db instance if possible, but for simplicity with fake_db:
fake_users_db = _fake_users_db_storage


# --- User Utility Functions ---
def get_user_from_db(db: Dict[str, UserInDB], username: str) -> Optional[UserInDB]:
    """Fetches a user from the provided user database."""
    if username in db:
        return db[username]
    return None

def authenticate_user(db: Dict[str, UserInDB], username: str, password: str) -> Optional[UserInDB]:
    """Authenticates a user by checking username and password."""
    user = get_user_from_db(db, username)
    if not user:
        return None # User not found
    if not verify_password(password, user.hashed_password):
        return None # Invalid password
    return user # Authentication successful

# --- Token Creation ---
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Creates a new JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# --- Token Verification / Current User Dependency ---
# The tokenUrl should point to your token-issuing endpoint, e.g., "/token"
# This path is relative to the application root.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    """Decodes JWT token to get the current user. Raises HTTPException for errors."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: Optional[str] = payload.get("sub")
        if username is None:
            raise credentials_exception
        scopes: List[str] = payload.get("scopes", []) # Get scopes if present
        token_data = TokenData(username=username, scopes=scopes)
    except JWTError as e:
        print(f"JWTError: {e}") # Log the error for debugging
        raise credentials_exception

    user_in_db = get_user_from_db(fake_users_db, token_data.username)
    if user_in_db is None:
        raise credentials_exception

    # Return a User model, not UserInDB, to avoid leaking hashed_password to client.
    # The roles assigned to the user for this session are taken from the token's 'scopes'.
    if user_in_db:
        # Create User object, but override roles with those from the token
        user_data_for_model = user_in_db.dict(exclude={"hashed_password", "roles"})
        return User(**user_data_for_model, roles=token_data.scopes)

    # This part should ideally not be reached if username from token must exist in DB
    raise credentials_exception


async def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    """
    Verifies if the current user (obtained from `get_current_user`) is active.
    This is a dependency that can be used in path operations requiring an active user.
    """
    if current_user.disabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")
    return current_user

# --- Role-Specific Dependency Functions ---

async def get_current_admin_user(current_user: User = Depends(get_current_active_user)) -> User:
    """Checks if the current active user has the ADMIN role."""
    if UserRoles.ADMIN not in current_user.roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions: Admin role required"
        )
    return current_user

async def get_current_analyst_user(current_user: User = Depends(get_current_active_user)) -> User:
    """Checks if the current active user has the ANALYST role."""
    if UserRoles.ANALYST not in current_user.roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions: Analyst role required"
        )
    return current_user

async def get_current_agent_user(current_user: User = Depends(get_current_active_user)) -> User:
    """Checks if the current active user has the AGENT role."""
    if UserRoles.AGENT not in current_user.roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions: Agent role required"
        )
    return current_user

# Optional: Generic role checker (not strictly required by the prompt, but good for flexibility)
# async def require_roles(required_roles: List[UserRoles], current_user: User = Depends(get_current_active_user)) -> User:
#     """Checks if the current active user has all specified roles."""
#     for role in required_roles:
#         if role not in current_user.roles:
#             raise HTTPException(
#                 status_code=status.HTTP_403_FORBIDDEN,
#                 detail=f"Not enough permissions: Missing role(s) - {', '.join(r.value for r in required_roles)}"
#             )
#     return current_user

# Example of how a protected route might look (this would typically go in your API routes file):
#
# from fastapi import APIRouter
# from .auth import get_current_active_user, User # Assuming auth.py is in the same directory
#
# router = APIRouter()
#
# @router.get("/users/me/", response_model=User)
# async def read_users_me(current_user: User = Depends(get_current_active_user)):
#     """Fetches details for the currently authenticated active user."""
#     return current_user
#
# @router.get("/items/")
# async def read_items(token: str = Depends(oauth2_scheme)): # Or use get_current_active_user for full user object
#     """Example of an endpoint that just requires a valid token, not necessarily an active user check."""
#     return {"token": token, "message": "Items accessible with valid token."}

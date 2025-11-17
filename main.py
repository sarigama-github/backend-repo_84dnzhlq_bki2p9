import os
from datetime import datetime, timedelta, date
from typing import Optional, List, Literal

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field

from sqlalchemy import (
    Column,
    String,
    Integer,
    Float,
    Date,
    DateTime,
    Text,
    ForeignKey,
    text,
)
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from sqlalchemy.sql import select

# ----------------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------------
SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-key-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

# Prefer PostgreSQL if provided, otherwise fall back to SQLite (so server always boots)
_env_db = os.getenv("DATABASE_URL", "").strip()
if _env_db:
    DATABASE_URL = _env_db
else:
    # Non-prod fallback to avoid startup failures when Postgres is unavailable
    DATABASE_URL = "sqlite+aiosqlite:///./app.db"

engine = create_async_engine(DATABASE_URL, echo=False, future=True)
async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
Base = declarative_base()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# ----------------------------------------------------------------------------
# DB Models
# ----------------------------------------------------------------------------
class UserModel(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(120), nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    updated_at = Column(DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP"))

    transactions = relationship("TransactionModel", back_populates="user", cascade="all, delete-orphan")


class TransactionModel(Base):
    __tablename__ = "transactions"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    type = Column(String(10), nullable=False)  # income | expense
    category = Column(String(64), nullable=False)
    amount = Column(Float, nullable=False)
    date = Column(Date, nullable=False)
    note = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    updated_at = Column(DateTime, nullable=False, server_default=text("CURRENT_TIMESTAMP"))

    user = relationship("UserModel", back_populates="transactions")

# ----------------------------------------------------------------------------
# Pydantic Schemas
# ----------------------------------------------------------------------------
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class UserRegister(BaseModel):
    name: str = Field(..., min_length=1)
    email: EmailStr
    password: str = Field(..., min_length=6)

class UserOut(BaseModel):
    id: int
    name: str
    email: EmailStr

    class Config:
        from_attributes = True

class TransactionIn(BaseModel):
    type: Literal["income", "expense"]
    category: str
    amount: float = Field(..., gt=0)
    date: date
    note: Optional[str] = None

class TransactionOut(TransactionIn):
    id: int

    class Config:
        from_attributes = True

class ReportItem(BaseModel):
    label: str
    income: float
    expense: float
    balance: float

# ----------------------------------------------------------------------------
# Auth helpers
# ----------------------------------------------------------------------------

def verify_password(plain_password: str, password_hash: str) -> bool:
    return pwd_context.verify(plain_password, password_hash)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_db() -> AsyncSession:
    async with async_session() as session:
        yield session

async def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)) -> UserModel:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: Optional[int] = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    result = await db.execute(select(UserModel).where(UserModel.id == int(user_id)))
    user = result.scalar_one_or_none()
    if user is None:
        raise credentials_exception
    return user

# ----------------------------------------------------------------------------
# App setup
# ----------------------------------------------------------------------------
app = FastAPI(title="Personal Finance API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------------------------------------------------------------
# Health & test
# ----------------------------------------------------------------------------
@app.get("/")
async def read_root():
    return {"message": "Personal Finance Backend is running"}

@app.get("/test")
async def test_database():
    info = {
        "backend": "✅ Running",
        "database_url": DATABASE_URL,
        "using_sqlite_fallback": DATABASE_URL.startswith("sqlite"),
        "connection_status": "Not Connected",
        "database": "❌ Not Available",
    }
    try:
        async with engine.begin() as conn:
            # ensure tables without blocking startup generally
            await conn.run_sync(Base.metadata.create_all)
            await conn.execute(text("SELECT 1"))
            info["database"] = "✅ Available"
            info["connection_status"] = "Connected"
    except Exception as e:
        info["database"] = f"❌ Error: {str(e)[:160]}"
    return info

# ----------------------------------------------------------------------------
# Auth routes
# ----------------------------------------------------------------------------
@app.post("/auth/register", response_model=UserOut)
async def register(payload: UserRegister, db: AsyncSession = Depends(get_db)):
    # Ensure tables exist lazily
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    result = await db.execute(select(UserModel).where(UserModel.email == payload.email))
    existing = result.scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    user = UserModel(
        name=payload.name,
        email=payload.email,
        password_hash=get_password_hash(payload.password),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user

@app.post("/auth/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(UserModel).where(UserModel.email == form_data.username))
    user = result.scalar_one_or_none()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    access_token = create_access_token({"sub": str(user.id)})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/auth/me", response_model=UserOut)
async def me(current_user: UserModel = Depends(get_current_user)):
    return current_user

# ----------------------------------------------------------------------------
# Transactions
# ----------------------------------------------------------------------------
@app.post("/transactions", response_model=TransactionOut)
async def create_transaction(payload: TransactionIn, db: AsyncSession = Depends(get_db), current_user: UserModel = Depends(get_current_user)):
    tx = TransactionModel(
        user_id=current_user.id,
        type=payload.type,
        category=payload.category,
        amount=payload.amount,
        date=payload.date,
        note=payload.note,
    )
    db.add(tx)
    await db.commit()
    await db.refresh(tx)
    return tx

@app.get("/transactions", response_model=List[TransactionOut])
async def list_transactions(
    from_date: Optional[date] = None,
    to_date: Optional[date] = None,
    ttype: Optional[Literal["income", "expense"]] = None,
    db: AsyncSession = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    query = select(TransactionModel).where(TransactionModel.user_id == current_user.id)
    if from_date:
        query = query.where(TransactionModel.date >= from_date)
    if to_date:
        query = query.where(TransactionModel.date <= to_date)
    if ttype:
        query = query.where(TransactionModel.type == ttype)
    query = query.order_by(TransactionModel.date.desc(), TransactionModel.id.desc())

    result = await db.execute(query)
    items = result.scalars().all()
    return items

# ----------------------------------------------------------------------------
# Reports
# ----------------------------------------------------------------------------
@app.get("/reports/summary", response_model=List[ReportItem])
async def reports_summary(
    period: Literal["daily", "monthly", "yearly"] = "monthly",
    from_date: Optional[date] = None,
    to_date: Optional[date] = None,
    db: AsyncSession = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    # Build date_trunc unit
    unit = "day" if period == "daily" else ("month" if period == "monthly" else "year")

    # SQLite compatible formatting
    if DATABASE_URL.startswith("sqlite"):
        # compute via SQL groupings compatible with SQLite
        fmt = "%Y-%m-%d" if unit == "day" else ("%Y-%m" if unit == "month" else "%Y")
        conditions = ["user_id = :uid"]
        params = {"uid": current_user.id}
        if from_date:
            conditions.append("date >= :from_date")
            params["from_date"] = from_date
        if to_date:
            conditions.append("date <= :to_date")
            params["to_date"] = to_date
        where_clause = " AND ".join(conditions)
        sql = text(
            f"""
            SELECT strftime('{fmt}', date) as label,
                   SUM(CASE WHEN type='income' THEN amount ELSE 0 END) AS income,
                   SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) AS expense
            FROM transactions
            WHERE {where_clause}
            GROUP BY 1
            ORDER BY 1
            """
        )
        result = await db.execute(sql, params)
    else:
        # PostgreSQL version
        conditions = [text("user_id = :uid")]
        params = {"uid": current_user.id}
        if from_date:
            conditions.append(text("date >= :from_date"))
            params["from_date"] = from_date
        if to_date:
            conditions.append(text("date <= :to_date"))
            params["to_date"] = to_date
        where_clause = text(" AND ").join(conditions)
        sql = text(
            f"""
            SELECT to_char(date_trunc('{unit}', date),
                           CASE WHEN '{unit}'='day' THEN 'YYYY-MM-DD'
                                WHEN '{unit}'='month' THEN 'YYYY-MM'
                                ELSE 'YYYY' END) as label,
                   SUM(CASE WHEN type='income' THEN amount ELSE 0 END) AS income,
                   SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) AS expense
            FROM transactions
            WHERE {where_clause.text}
            GROUP BY 1
            ORDER BY 1
            """
        )
        result = await db.execute(sql, params)

    rows = result.fetchall()
    data = []
    for r in rows:
        income = float(r.income or 0)
        expense = float(r.expense or 0)
        data.append(ReportItem(label=r.label, income=income, expense=expense, balance=income - expense))
    return data


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)

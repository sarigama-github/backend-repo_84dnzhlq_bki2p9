"""
App Schemas

Define MongoDB collection schemas using Pydantic models.
Each class name corresponds to a collection with its lowercase name.
- User -> "user"
- Transaction -> "transaction"
"""

from pydantic import BaseModel, Field, EmailStr, constr
from typing import Optional, Literal
from datetime import date, datetime

class User(BaseModel):
    """
    Users collection schema
    Collection name: "user"
    """
    name: constr(strip_whitespace=True, min_length=1) = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address")
    password_hash: str = Field(..., description="Hashed password (bcrypt)")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class Transaction(BaseModel):
    """
    Transactions for personal finance
    Collection name: "transaction"
    """
    user_id: str = Field(..., description="Owner user id as string")
    type: Literal["income", "expense"] = Field(..., description="Income or expense")
    category: str = Field(..., description="Category such as salary, food, rent")
    amount: float = Field(..., gt=0, description="Positive amount")
    date: date = Field(..., description="Transaction date")
    note: Optional[str] = Field(None, description="Optional note")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import Integer, String

from  app.core.database import Base

class TestUser(Base):
    __tablename__ = "test_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    email: Mapped[str] = mapped_column(String, unique=True, nullable=False)
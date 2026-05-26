from fastapi import FastAPI, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from sqlalchemy import select
from .core.database import engine, AsyncSessionLocal, Base
from app.module.testDB.model import TestUser
from app.shared.auth.router import router

app = FastAPI(title="ERP – ATS API", version="1.0.0")

app.include_router(router, prefix="/api/v1/auth", tags=["Auth"])

@app.get("/")
def home():
    return {"Hello": "World"}


@app.get("/something")
def something():
    return {"Welcome to": "ETX ERP Backend"}

@app.get("/health")
def health():
    return {"status": "ok"}


# @app.on_event("startup")
# async def startup():

#     # CREATE TABLES
#     async with engine.begin() as conn:
#         await conn.run_sync(Base.metadata.create_all)

#     # INSERT TEST DATA
#     async with AsyncSessionLocal() as session:

#         user = TestUser(
#             name="Ganpat",
#             email="ganpat@test.com"
#         )

#         session.add(user)

#         await session.commit()

#         print("Dummy user inserted ✅")

#     # READ TEST DATA
#     async with AsyncSessionLocal() as session:

#         result = await session.execute(
#             select(TestUser)
#         )

#         users = result.scalars().all()

#         print(users)

#     print("Database working perfectly ✅")

@app.get("/db-test")
def test_db_connection(db: AsyncSession = Depends(AsyncSessionLocal)):
    try:
        # Executes a simple query to check connectivity
        db.execute(text("SELECT 1"))
        return {"status": "success", "message": "Database is connected!"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database connection failed: {str(e)}")
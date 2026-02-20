from fastapi import FastAPI

from .database import engine, Base
from .routes import auth

# create tables on startup (for simple deployments)
Base.metadata.create_all(bind=engine)

app = FastAPI(title="FastAPI Auth Example")

app.include_router(auth.router)


@app.get("/")
def root():
    return {"message": "Welcome to the authentication API"}

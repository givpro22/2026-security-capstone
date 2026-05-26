from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import auth
import keys
import ws
from database import Base, engine

Base.metadata.create_all(bind=engine)

app = FastAPI(title="E2EE Chat", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(keys.router)
app.include_router(ws.router)


@app.get("/")
def root():
    return {"name": "e2ee-chat", "status": "ok"}

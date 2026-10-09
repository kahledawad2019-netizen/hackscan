"""FastAPI endpoints that delegate to `repository` (cross-file flows)."""

from fastapi import FastAPI

from . import repository

api = FastAPI()


@api.get("/users/{name}")
def get_user(name: str):
    return {"user": repository.find_user(name)}


@api.get("/users/safe/{name}")
def get_user_safely(name: str):
    return {"user": repository.find_user_safely(name)}


@api.delete("/users/{user_id}")
def remove_user(user_id: str):
    repository.delete_user(int(user_id))
    return {"ok": True}


def nightly_job():
    for table in ("sessions", "audit"):
        repository.archive(table)

"""Intentionally vulnerable route examples; risky endpoints are disabled by default."""
import os
import sqlite3
from fastapi import APIRouter, HTTPException, Query
from . import vulnerable_helpers as helpers

router = APIRouter()
_DB = sqlite3.connect(":memory:", check_same_thread=False)
_DB.execute("CREATE TABLE IF NOT EXISTS demo_items (name TEXT)")
_DB.execute("INSERT INTO demo_items VALUES ('sample')")


# INTENTIONALLY VULNERABLE — FOR AUTHORIZED LOCAL TESTING ONLY
def lookup_item_unsafe(user_input: str):
    """SQL injection fixture over a synthetic in-memory database."""
    return _DB.execute("SELECT name FROM demo_items WHERE name = '" + user_input + "'").fetchall()


# INTENTIONALLY VULNERABLE — FOR AUTHORIZED LOCAL TESTING ONLY
def expose_internal_error():
    """Example of returning internal exception details to a caller."""
    try:
        raise RuntimeError("synthetic internal implementation detail")
    except Exception as exc:
        return {"error": str(exc)}


def _require_opt_in():
    if os.getenv("LAB_ENABLE_DEMOS") != "true":
        raise HTTPException(status_code=404, detail="Demo routes are disabled")


@router.get("/demo/sql")
def sql_demo(q: str = Query(..., max_length=80)):
    _require_opt_in()
    # Only synthetic rows; this route is disabled unless explicitly enabled.
    return {"rows": lookup_item_unsafe(q)}


@router.get("/demo/error")
def error_demo():
    _require_opt_in()
    return expose_internal_error()


@router.get("/health")
def health():
    return {"status": "ok"}


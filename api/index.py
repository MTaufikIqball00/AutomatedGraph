"""Vercel Serverless Function entry point for Automated GraphRAG.

Vercel's Python runtime natively looks for an ASGI/WSGI callable named `app`
in files located inside the `/api` directory.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Mark VERCEL environment flag if executing in serverless deployment
os.environ.setdefault("VERCEL", "1")

# Ensure the root project repository is in Python sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Import the pre-configured FastAPI application instance
from backend.main import app

__all__ = ["app"]

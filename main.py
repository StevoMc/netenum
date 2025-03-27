import asyncio
import base64
import concurrent.futures
import ipaddress
import json
import logging
import os
import re
import secrets
import subprocess
import threading
import time
import urllib.parse
from dataclasses import asdict, dataclass
from queue import Queue
from typing import List, Optional

import uvicorn
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.routing import APIRouter
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from middleware.auth import TokenAuthMiddleware
from middleware.ratelimiter import RateLimiterMiddleware

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Data models


@dataclass
class Port:
    port: int
    state: str
    service: str
    version: Optional[str] = None
    http_response: Optional[str] = None
    screenshot: Optional[str] = None


@dataclass
class Host:
    ip: str
    mac: Optional[str] = None
    vendor: Optional[str] = None
    hostname: Optional[str] = None
    os: Optional[str] = None
    icon: Optional[str] = None
    open_ports: List[Port] = None


@dataclass
class Scan:
    network: str
    hosts: List[Host]
    start: float
    end: Optional[float] = None


@dataclass
class State:
    scanning: bool
    current_host: Optional[str]


class ScanInput(BaseModel):
    network: str


app = FastAPI(
    title="NetEnum API",
    description="API for the NetEnum application",
    version="1.0.0",
    root_path="/api/v1",
    contact={
        "name": "Steven McGough",
        # "url": "https://netenum.example.com/support",
    },
    license_info={
        "name": "MIT License",
        "url": "https://opensource.org/licenses/MIT",
    },
)

# Configure templates
templates = Jinja2Templates(directory="templates")
scanning_log = []

# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# Check for existing token file
token_file = "api_token.txt"
if os.path.exists(token_file):
    with open(token_file, "r") as f:
        token = f.read().strip()
    logger.debug(f"Using existing token from {token_file}")
else:
    token = secrets.token_hex(32)
    # Save token to file for persistence
    with open(token_file, "w") as f:
        f.write(token)
    logger.debug(f"Generated and saved new token to {token_file}")

logger.info("="*100)
logger.info(f"\033[93mAPI TOKEN: {token}\033[0m")
logger.info("="*100 + "\n")

app.add_middleware(
    TokenAuthMiddleware,
    token=token,
    # TODO: Exclude paths does not work as expected
    exclude_paths=["/", "/docs", "/api/v1/"],
)
app.add_middleware(
    RateLimiterMiddleware,
    max_requests=250,
    window_seconds=60
)

# Include existing routers
router = APIRouter()
app.include_router(router)

# Scanning utility functions

state = State(scanning=False, current_host=None)

# Make sure the scan directory exists else create it
if not os.path.exists("scans"):
    os.makedirs("scans", exist_ok=True)


def get_icon(os: str) -> str:
    if type(os) is not str:
        return ""

    if "windows" in os.lower():
        return "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iaXNvLTg4NTktMSI/Pgo8IS0tIFVwbG9hZGVkIHRvOiBTVkcgUmVwbywgd3d3LnN2Z3JlcG8uY29tLCBHZW5lcmF0b3I6IFNWRyBSZXBvIE1peGVyIFRvb2xzIC0tPgo8c3ZnIGZpbGw9IiMwMDAwMDAiIGhlaWdodD0iODAwcHgiIHdpZHRoPSI4MDBweCIgdmVyc2lvbj0iMS4xIiBpZD0iTGF5ZXJfMSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayIgCgkgdmlld0JveD0iMCAwIDMwNSAzMDUiIHhtbDpzcGFjZT0icHJlc2VydmUiPgo8ZyBpZD0iWE1MSURfMTA4XyI+Cgk8cGF0aCBpZD0iWE1MSURfMTA5XyIgZD0iTTEzOS45OTksMjUuNzc1djExNi43MjRjMCwxLjM4MSwxLjExOSwyLjUsMi41LDIuNUgzMDIuNDZjMS4zODEsMCwyLjUtMS4xMTksMi41LTIuNVYyLjUKCQljMC0wLjcyNi0wLjMxNS0xLjQxNi0wLjg2NC0xLjg5MWMtMC41NDgtMC40NzUtMS4yNzUtMC42ODctMS45OTYtMC41ODNMMTQyLjEzOSwyMy4zMDEKCQlDMTQwLjkxLDIzLjQ4LDEzOS45OTksMjQuNTM0LDEzOS45OTksMjUuNzc1eiIvPgoJPHBhdGggaWQ9IlhNTElEXzExMF8iIGQ9Ik0xMjIuNTAxLDI3OS45NDhjMC42MDEsMCwxLjE4Ni0wLjIxNiwxLjY0NC0wLjYxNmMwLjU0NC0wLjQ3NSwwLjg1Ni0xLjE2MiwwLjg1Ni0xLjg4NFYxNjIuNQoJCWMwLTEuMzgxLTEuMTE5LTIuNS0yLjUtMi41SDIuNTkyYy0wLjY2MywwLTEuMjk5LDAuMjYzLTEuNzY4LDAuNzMyYy0wLjQ2OSwwLjQ2OS0wLjczMiwxLjEwNS0wLjczMiwxLjc2OGwwLjAwNiw5OC41MTUKCQljMCwxLjI1LDAuOTIzLDIuMzA3LDIuMTYsMi40NzdsMTE5LjkwMywxNi40MzRDMTIyLjI3NCwyNzkuOTQsMTIyLjM4OCwyNzkuOTQ4LDEyMi41MDEsMjc5Ljk0OHoiLz4KCTxwYXRoIGlkPSJYTUxJRF8xMzhfIiBkPSJNMi42MDksMTQ0Ljk5OWgxMTkuODkyYzEuMzgxLDAsMi41LTEuMTE5LDIuNS0yLjVWMjguNjgxYzAtMC43MjItMC4zMTItMS40MDgtMC44NTUtMS44ODMKCQljLTAuNTQzLTAuNDc1LTEuMjYxLTAuNjkzLTEuOTgxLTAuNTk0TDIuMTY0LDQyLjVDMC45MjMsNDIuNjY5LTAuMDAxLDQzLjcyOCwwLDQ0Ljk4bDAuMTA5LDk3LjUyMQoJCUMwLjExMSwxNDMuODgxLDEuMjMsMTQ0Ljk5OSwyLjYwOSwxNDQuOTk5eiIvPgoJPHBhdGggaWQ9IlhNTElEXzE2OV8iIGQ9Ik0zMDIuNDYsMzA1YzAuNTk5LDAsMS4xODItMC4yMTUsMS42NC0wLjYxM2MwLjU0Ni0wLjQ3NSwwLjg2LTEuMTYzLDAuODYtMS44ODdsMC4wNC0xNDAKCQljMC0wLjY2My0wLjI2My0xLjI5OS0wLjczMi0xLjc2OGMtMC40NjktMC40NjktMS4xMDUtMC43MzItMS43NjgtMC43MzJIMTQyLjQ5OWMtMS4zODEsMC0yLjUsMS4xMTktMi41LDIuNXYxMTcuNDk2CgkJYzAsMS4yNDYsMC45MTgsMi4zMDIsMi4xNTEsMi40NzZsMTU5Ljk2MSwyMi41MDRDMzAyLjIyOCwzMDQuOTkyLDMwMi4zNDQsMzA1LDMwMi40NiwzMDV6Ii8+CjwvZz4KPC9zdmc+"
    if "linux" in os.lower():
        return "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iaXNvLTg4NTktMSI/Pgo8IS0tIFVwbG9hZGVkIHRvOiBTVkcgUmVwbywgd3d3LnN2Z3JlcG8uY29tLCBHZW5lcmF0b3I6IFNWRyBSZXBvIE1peGVyIFRvb2xzIC0tPgo8c3ZnIGZpbGw9IiMwMDAwMDAiIGhlaWdodD0iODAwcHgiIHdpZHRoPSI4MDBweCIgdmVyc2lvbj0iMS4xIiBpZD0iTGF5ZXJfMSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayIgCgkgdmlld0JveD0iMCAwIDMwNC45OTggMzA0Ljk5OCIgeG1sOnNwYWNlPSJwcmVzZXJ2ZSI+CjxnIGlkPSJYTUxJRF85MV8iPgoJPHBhdGggaWQ9IlhNTElEXzkyXyIgZD0iTTI3NC42NTksMjQ0Ljg4OGMtOC45NDQtMy42NjMtMTIuNzctOC41MjQtMTIuNC0xNS43NzdjMC4zODEtOC40NjYtNC40MjItMTQuNjY3LTYuNzAzLTE3LjExNwoJCWMxLjM3OC01LjI2NCw1LjQwNS0yMy40NzQsMC4wMDQtMzkuMjkxYy01LjgwNC0xNi45My0yMy41MjQtNDIuNzg3LTQxLjgwOC02OC4yMDRjLTcuNDg1LTEwLjQzOC03LjgzOS0yMS43ODQtOC4yNDgtMzQuOTIyCgkJYy0wLjM5Mi0xMi41MzEtMC44MzQtMjYuNzM1LTcuODIyLTQyLjUyNUMxOTAuMDg0LDkuODU5LDE3NC44MzgsMCwxNTUuODUxLDBjLTExLjI5NSwwLTIyLjg4OSwzLjUzLTMxLjgxMSw5LjY4NAoJCWMtMTguMjcsMTIuNjA5LTE1Ljg1NSw0MC4xLTE0LjI1Nyw1OC4yOTFjMC4yMTksMi40OTEsMC40MjUsNC44NDQsMC41NDUsNi44NTNjMS4wNjQsMTcuODE2LDAuMDk2LDI3LjIwNi0xLjE3LDMwLjA2CgkJYy0wLjgxOSwxLjg2NS00Ljg1MSw3LjE3My05LjExOCwxMi43OTNjLTQuNDEzLDUuODEyLTkuNDE2LDEyLjQtMTMuNTE3LDE4LjUzOWMtNC44OTMsNy4zODctOC44NDMsMTguNjc4LTEyLjY2MywyOS41OTcKCQljLTIuNzk1LDcuOTktNS40MzUsMTUuNTM3LTguMDA1LDIwLjA0N2MtNC44NzEsOC42NzYtMy42NTksMTYuNzY2LTIuNjQ3LDIwLjUwNWMtMS44NDQsMS4yODEtNC41MDgsMy44MDMtNi43NTcsOC41NTcKCQljLTIuNzE4LDUuOC04LjIzMyw4LjkxNy0xOS43MDEsMTEuMTIyYy01LjI3LDEuMDc4LTguOTA0LDMuMjk0LTEwLjgwNCw2LjU4NmMtMi43NjUsNC43OTEtMS4yNTksMTAuODExLDAuMTE1LDE0LjkyNQoJCWMyLjAzLDYuMDQ4LDAuNzY1LDkuODc2LTEuNTM1LDE2LjgyNmMtMC41MywxLjYwNC0xLjEzMSwzLjQyLTEuNzQsNS40MjNjLTAuOTU5LDMuMTYxLTAuNjEzLDYuMDM1LDEuMDI2LDguNTQyCgkJYzQuMzMxLDYuNjIxLDE2Ljk2OSw4Ljk1NiwyOS45NzksMTAuNDkyYzcuNzY4LDAuOTIyLDE2LjI3LDQuMDI5LDI0LjQ5Myw3LjAzNWM4LjA1NywyLjk0NCwxNi4zODgsNS45ODksMjMuOTYxLDYuOTEzCgkJYzEuMTUxLDAuMTQ1LDIuMjkxLDAuMjE4LDMuMzksMC4yMThjMTEuNDM0LDAsMTYuNi03LjU4NywxOC4yMzgtMTAuNzA0YzQuMTA3LTAuODM4LDE4LjI3Mi0zLjUyMiwzMi44NzEtMy44ODIKCQljMTQuNTc2LTAuNDE2LDI4LjY3OSwyLjQ2MiwzMi42NzQsMy4zNTdjMS4yNTYsMi40MDQsNC41NjcsNy44OTUsOS44NDUsMTAuNzI0YzIuOTAxLDEuNTg2LDYuOTM4LDIuNDk1LDExLjA3MywyLjQ5NQoJCWMwLjAwMSwwLDAsMCwwLjAwMSwwYzQuNDE2LDAsMTIuODE3LTEuMDQ0LDE5LjQ2Ni04LjAzOWM2LjYzMi03LjAyOCwyMy4yMDItMTYsMzUuMzAyLTIyLjU1MWMyLjctMS40NjIsNS4yMjYtMi44Myw3LjQ0MS00LjA2NQoJCWM2Ljc5Ny0zLjc2OCwxMC41MDYtOS4xNTIsMTAuMTc1LTE0Ljc3MUMyODIuNDQ1LDI1MC45MDUsMjc5LjM1NiwyNDYuODExLDI3NC42NTksMjQ0Ljg4OHogTTEyNC4xODksMjQzLjUzNQoJCWMtMC44NDYtNS45Ni04LjUxMy0xMS44NzEtMTcuMzkyLTE4LjcxNWMtNy4yNi01LjU5Ny0xNS40ODktMTEuOTQtMTcuNzU2LTE3LjMxMmMtNC42ODUtMTEuMDgyLTAuOTkyLTMwLjU2OCw1LjQ0Ny00MC42MDIKCQljMy4xODItNS4wMjQsNS43ODEtMTIuNjQzLDguMjk1LTIwLjAxMWMyLjcxNC03Ljk1Niw1LjUyMS0xNi4xODIsOC42Ni0xOS43ODNjNC45NzEtNS42MjIsOS41NjUtMTYuNTYxLDEwLjM3OS0yNS4xODIKCQljNC42NTUsNC40NDQsMTEuODc2LDEwLjA4MywxOC41NDcsMTAuMDgzYzEuMDI3LDAsMi4wMjQtMC4xMzQsMi45NzctMC40MDNjNC41NjQtMS4zMTgsMTEuMjc3LTUuMTk3LDE3Ljc2OS04Ljk0NwoJCWM1LjU5Ny0zLjIzNCwxMi40OTktNy4yMjIsMTUuMDk2LTcuNTg1YzQuNDUzLDYuMzk0LDMwLjMyOCw2My42NTUsMzIuOTcyLDgyLjA0NGMyLjA5MiwxNC41NS0wLjExOCwyNi41NzgtMS4yMjksMzEuMjg5CgkJYy0wLjg5NC0wLjEyMi0xLjk2LTAuMjIxLTMuMDgtMC4yMjFjLTcuMjA3LDAtOS4xMTUsMy45MzQtOS42MTIsNi4yODNjLTEuMjc4LDYuMTAzLTEuNDEzLDI1LjYxOC0xLjQyNywzMC4wMDMKCQljLTIuNjA2LDMuMzExLTE1Ljc4NSwxOC45MDMtMzQuNzA2LDIxLjcwNmMtNy43MDcsMS4xMi0xNC45MDQsMS42ODgtMjEuMzksMS42ODhjLTUuNTQ0LDAtOS4wODItMC40MjgtMTAuNTUxLTAuNjUxbC05LjUwOC0xMC44NzkKCQlDMTIxLjQyOSwyNTQuNDg5LDEyNS4xNzcsMjUwLjU4MywxMjQuMTg5LDI0My41MzV6IE0xMzYuMjU0LDY0LjE0OWMtMC4yOTcsMC4xMjgtMC41ODksMC4yNjUtMC44NzYsMC40MTEKCQljLTAuMDI5LTAuNjQ0LTAuMDk2LTEuMjk3LTAuMTk5LTEuOTUyYy0xLjAzOC01Ljk3NS01LTEwLjMxMi05LjQxOS0xMC4zMTJjLTAuMzI3LDAtMC42NTYsMC4wMjUtMS4wMTcsMC4wOAoJCWMtMi42MjksMC40MzgtNC42OTEsMi40MTMtNS44MjEsNS4yMTNjMC45OTEtNi4xNDQsNC40NzItMTAuNjkzLDguNjAyLTEwLjY5M2M0Ljg1LDAsOC45NDcsNi41MzYsOC45NDcsMTQuMjcyCgkJQzEzNi40NzEsNjIuMTQzLDEzNi40LDYzLjExMywxMzYuMjU0LDY0LjE0OXogTTE3My45NCw2OC43NTZjMC40NDQtMS40MTQsMC42ODQtMi45NDQsMC42ODQtNC41MzIKCQljMC03LjAxNC00LjQ1LTEyLjUwOS0xMC4xMzEtMTIuNTA5Yy01LjU1MiwwLTEwLjA2OSw1LjYxMS0xMC4wNjksMTIuNTA5YzAsMC40NywwLjAyMywwLjk0MSwwLjA2NywxLjQxMQoJCWMtMC4yOTQtMC4xMTMtMC41ODEtMC4yMjMtMC44NjEtMC4zMjljLTAuNjM5LTEuOTM1LTAuOTYyLTMuOTU0LTAuOTYyLTYuMDE1YzAtOC4zODcsNS4zNi0xNS4yMTEsMTEuOTUtMTUuMjExCgkJYzYuNTg5LDAsMTEuOTUsNi44MjQsMTEuOTUsMTUuMjExQzE3Ni41NjgsNjIuNzgsMTc1LjYwNSw2Ni4xMSwxNzMuOTQsNjguNzU2eiBNMTY5LjA4MSw4NS4wOAoJCWMtMC4wOTUsMC40MjQtMC4yOTcsMC42MTItMi41MzEsMS43NzRjLTEuMTI4LDAuNTg3LTIuNTMyLDEuMzE4LTQuMjg5LDIuMzg4bC0xLjE3NCwwLjcxMWMtNC43MTgsMi44Ni0xNS43NjUsOS41NTktMTguNzY0LDkuOTUyCgkJYy0yLjAzNywwLjI3NC0zLjI5Ny0wLjUxNi02LjEzLTIuNDQxYy0wLjYzOS0wLjQzNS0xLjMxOS0wLjg5Ny0yLjA0NC0xLjM2MmMtNS4xMDctMy4zNTEtOC4zOTItNy4wNDItOC43NjMtOC40ODUKCQljMS42NjUtMS4yODcsNS43OTItNC41MDgsNy45MDUtNi40MTVjNC4yODktMy45ODgsOC42MDUtNi42NjgsMTAuNzQxLTYuNjY4YzAuMTEzLDAsMC4yMTUsMC4wMDgsMC4zMjEsMC4wMjgKCQljMi41MSwwLjQ0Myw4LjcwMSwyLjkxNCwxMy4yMjMsNC43MThjMi4wOSwwLjgzNCwzLjg5NSwxLjU1NCw1LjE2NSwyLjAxQzE2Ni43NDIsODIuNjY0LDE2OC44MjgsODQuNDIyLDE2OS4wODEsODUuMDh6CgkJIE0yMDUuMDI4LDI3MS40NWMyLjI1Ny0xMC4xODEsNC44NTctMjQuMDMxLDQuNDM2LTMyLjE5NmMtMC4wOTctMS44NTUtMC4yNjEtMy44NzQtMC40Mi01LjgyNgoJCWMtMC4yOTctMy42NS0wLjczOC05LjA3NS0wLjI4My0xMC42ODRjMC4wOS0wLjA0MiwwLjE5LTAuMDc4LDAuMzAxLTAuMTA5YzAuMDE5LDQuNjY4LDEuMDMzLDEzLjk3OSw4LjQ3OSwxNy4yMjYKCQljMi4yMTksMC45NjgsNC43NTUsMS40NTgsNy41MzcsMS40NThjNy40NTksMCwxNS43MzUtMy42NTksMTkuMTI1LTcuMDQ5YzEuOTk2LTEuOTk2LDMuNjc1LTQuNDM4LDQuODUxLTYuMzcyCgkJYzAuMjU3LDAuNzUzLDAuNDE1LDEuNzM3LDAuMzMyLDMuMDA1Yy0wLjQ0Myw2Ljg4NSwyLjkwMywxNi4wMTksOS4yNzEsMTkuMzg1bDAuOTI3LDAuNDg3YzIuMjY4LDEuMTksOC4yOTIsNC4zNTMsOC4zODksNS44NTMKCQljLTAuMDAxLDAuMDAxLTAuMDUxLDAuMTc3LTAuMzg3LDAuNDg5Yy0xLjUwOSwxLjM3OS02LjgyLDQuMDkxLTExLjk1Niw2LjcxNGMtOS4xMTEsNC42NTItMTkuNDM4LDkuOTI1LTI0LjA3NiwxNC44MDMKCQljLTYuNTMsNi44NzItMTMuOTE2LDExLjQ4OC0xOC4zNzYsMTEuNDg4Yy0wLjUzNywwLTEuMDI2LTAuMDY4LTEuNDYxLTAuMjA2QzIwNi44NzMsMjg4LjQwNiwyMDIuODg2LDI4MS40MTcsMjA1LjAyOCwyNzEuNDV6CgkJIE0zOS45MTcsMjQ1LjQ3N2MtMC40OTQtMi4zMTItMC44ODQtNC4xMzctMC40NjUtNS45MDVjMC4zMDQtMS4zMSw2Ljc3MS0yLjcxNCw5LjUzMy0zLjMxM2MzLjg4My0wLjg0Myw3Ljg5OS0xLjcxNCwxMC41MjUtMy4zMDgKCQljMy41NTEtMi4xNTEsNS40NzQtNi4xMTgsNy4xNy05LjYxOGMxLjIyOC0yLjUzMSwyLjQ5Ni01LjE0OCw0LjAwNS02LjAwN2MwLjA4NS0wLjA1LDAuMjE1LTAuMTA4LDAuNDYzLTAuMTA4CgkJYzIuODI3LDAsOC43NTksNS45NDMsMTIuMTc3LDExLjI2MmMwLjg2NywxLjM0MSwyLjQ3Myw0LjAyOCw0LjMzMSw3LjEzOWM1LjU1Nyw5LjI5OCwxMy4xNjYsMjIuMDMzLDE3LjE0LDI2LjMwMQoJCWMzLjU4MSwzLjgzNyw5LjM3OCwxMS4yMTQsNy45NTIsMTcuNTQxYy0xLjA0NCw0LjkwOS02LjYwMiw4LjkwMS03LjkxMyw5Ljc4NGMtMC40NzYsMC4xMDgtMS4wNjUsMC4xNjMtMS43NTgsMC4xNjMKCQljLTcuNjA2LDAtMjIuNjYyLTYuMzI4LTMwLjc1MS05LjcyOGwtMS4xOTctMC41MDNjLTQuNTE3LTEuODk0LTExLjg5MS0zLjA4Ny0xOS4wMjItNC4yNDFjLTUuNjc0LTAuOTE5LTEzLjQ0NC0yLjE3Ni0xNC43MzItMy4zMTIKCQljLTEuMDQ0LTEuMTcxLDAuMTY3LTQuOTc4LDEuMjM1LTguMzM3YzAuNzY5LTIuNDE0LDEuNTYzLTQuOTEsMS45OTgtNy41MjNDNDEuMjI1LDI1MS41OTYsNDAuNDk5LDI0OC4yMDMsMzkuOTE3LDI0NS40Nzd6Ii8+CjwvZz4KPC9zdmc+"
    return ""


def validate_cidr(cidr: str):
    try:
        return ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid network CIDR")


def safe_run_command(cmd: List[str]) -> subprocess.CompletedProcess:
    logger.debug(f"Running command: {' '.join(cmd)}")
    try:
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Command error: {e}")
        raise e


def save_scan_to_json(scan: Scan, filename: str = "scan_results.json") -> None:
    try:
        with open(filename, 'w') as f:
            json.dump(asdict(scan), f, indent=4)
        logger.debug(f"Scan results saved to {filename}")
    except Exception as e:
        logger.error(f"Error saving scan to JSON: {e}")


def load_scan_from_json(filename: str = "scan_results.json") -> Scan:
    try:
        with open(filename) as f:
            data = json.load(f)
        scan = Scan(**data)
        logger.debug(f"Scan results loaded from {filename}")
        return scan
    except Exception as e:
        logger.error(f"Error loading scan from JSON: {e}")


def ping_sweep(network: str, scan: Scan) -> List[Host]:
    alive_hosts = []
    logger.info(f"Starting ping sweep on network: {str(network)}")
    try:
        result = safe_run_command([
            "nmap",
            "-sn",
            "-PE",  # ICMP Echo
            "-PP",  # Timestamp
            "-PM",  # Netmask
            "-PS80,443",  # TCP SYN on common ports
            "-PA80,443",  # TCP ACK on the same ports
            "-PU53",      # UDP Ping on port 53
            "-T4",
            "--max-retries", "5",
            "--host-timeout", "30s",
            "--trace",
            "--reason",
            "-oA", "scans/host_scan",
            "-v",
            str(network)
        ])

        logger.debug(result.stdout)

        # Parse results with better information extraction
        for i, line in enumerate(result.stdout.splitlines()):
            if "Nmap scan report for" in line and "down" not in line:
                parts = line.split()
                ip = parts[-1].strip("()")
                hostname = parts[-2] if "(" in line else None

                new_host = Host(ip=ip, hostname=hostname, open_ports=[])

                # Extract MAC address and vendor info if available
                for j in range(i+1, min(i+5, len(result.stdout.splitlines()))):
                    next_line = result.stdout.splitlines()[j]
                    if "MAC Address:" in next_line:
                        mac_parts = next_line.split(
                            "MAC Address:")[1].split("(")
                        new_host.mac = mac_parts[0].strip()
                        if len(mac_parts) > 1:
                            new_host.vendor = mac_parts[1].strip(")").strip()
                    elif "OS:" in next_line:
                        new_host.os = next_line.split("OS:")[1].strip()

                alive_hosts.append(new_host)
                scan.hosts.append(new_host)
                save_scan_to_json(scan)
                logger.info(
                    f"Host alive: {ip} ({hostname or 'No hostname'}) {new_host.mac or ''}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Ping sweep error: {e}")

    # Sort hosts by IP address for consistent output
    alive_hosts.sort(key=lambda x: [int(part) for part in x.ip.split(".")])

    logger.info(f"Ping sweep complete: found {len(alive_hosts)} alive hosts")
    return alive_hosts


def port_scan(host: Host, ports: List[int], scan: Scan) -> List[Port]:
    global state
    open_ports = []
    port_range = f"{ports[0]}-{ports[-1]}"
    logger.info(f"Scanning ports on {host.ip}: {port_range}")
    state.scanning = True
    state.current_host = host.ip
    try:
        result = safe_run_command(
            ["nmap", "-p", port_range, "-T3", "-sV", "-O", "--version-intensity", "3", "--open", "--host-timeout", "600s", "-oA", f"scans/port_scan_{host.ip.replace('.', '-')}", host.ip])
        for line in result.stdout.splitlines():
            logger.debug(line)
            if re.match(r"Running", line):
                host.os = line.split(":")[1].strip()
                host.icon = get_icon(host.os)

            elif re.match(r"Service Info", line) and host.os is None:
                result = re.search(r"OS: (.+)", line)
                host.os = result.group(1) if result else None
                host.icon = get_icon(host.os)
            elif re.match(r"\d+/tcp", line) and ("open" in line):
                parts = line.split()
                _port = int(parts[0].split("/")[0])
                open_ports.append(Port(
                    port=_port,
                    state=parts[1],
                    service=parts[2],
                    version=" ".join(parts[3:]) if len(parts) > 3 else None
                ))
                logger.info(
                    f"Open port on {host.ip}: {_port}/{parts[1]} {parts[2]}")
            else:
                continue
    except subprocess.CalledProcessError as e:
        logger.error(f"Port scan error on {host.ip}: {e}")
    host.open_ports = open_ports
    save_scan_to_json(scan)
    return open_ports


def http_scan(scan: Scan) -> Scan:
    logger.info("Starting HTTP scan on open ports")
    for host in scan.hosts:
        for port in (host.open_ports or []):
            # if "http" not in port.service:
            #     continue
            protocol = "https" if "ssl" in port.service else "http"
            curl_command = ["curl", "-s", "-i", "-L", "-m", "5"]
            if protocol == "https":
                curl_command.append("-k")
            curl_command.append(f"{protocol}://{host.ip}:{port.port}")
            try:
                result = safe_run_command(curl_command)
                if "HTTP/1.1 404 Not Found" in result.stdout:
                    continue

                port.http_response = result.stdout

                logger.debug(f"HTTP response from {host.ip}:{port.port}")

                # Capture a screenshot
                logger.info(f"Capturing screenshot of {host.ip}:{port.port}")
                subprocess.run(
                    [
                        "chromium-browser",
                        "--headless",
                        "--disable-gpu",
                        "--no-sandbox",
                        "--screenshot=screenshot.png",
                        "--window-size=1280,720",
                        "--ignore-certificate-errors",
                        "--virtual-time-budget=5000",
                        "--follow-redirects",
                        f"{protocol}://{host.ip}:{port.port}"
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False
                )

                if os.path.exists("screenshot.png"):
                    with open("screenshot.png", "rb") as f:
                        screenshot = f.read()
                    base64_screenshot = base64.b64encode(
                        screenshot).decode("utf-8")
                    url_encoded_screenshot = urllib.parse.quote(
                        base64_screenshot)
                    port.screenshot = url_encoded_screenshot

                    os.remove("screenshot.png")

                save_scan_to_json(scan)
            except subprocess.CalledProcessError:
                logger.warning(f"Failed HTTP request to {host.ip}:{port.port}")
                pass
    return scan


def run_scan(network="192.168.178.0/24"):
    global state
    scan = Scan(network=network, hosts=[], start=time.time())
    logger.info(f"Scan started for network: {network}")

    state.scanning = True

    alive_hosts = ping_sweep(network, scan)

    # Limit ports to minimize surface
    ports = list(range(1, 65536))

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        futures = {executor.submit(
            port_scan, h, ports, scan): h for h in alive_hosts}
        for future in concurrent.futures.as_completed(futures):
            host = futures[future]
            try:
                open_ports = future.result()
                scanning_log.append(
                    f"Open ports on {host.ip}: {[p.port for p in open_ports]}")
                logger.info(f"Completed port scan on {host.ip}")
            except Exception as e:
                scanning_log.append(f"Error processing {host.ip}: {e}")
                logger.error(f"Error processing {host.ip}: {e}")

    scan.end = time.time()
    for h in alive_hosts:
        scanning_log.append(f"Host: {h.ip} ({h.hostname})")
        logger.info(f"Host: {h.ip} ({h.hostname})")
        if h.open_ports:
            for p in h.open_ports:
                scanning_log.append(
                    f"  Port: {p.port}, Service: {p.service}, Version: {p.version}")
                logger.info(
                    f"  Port: {p.port}, Service: {p.service}, Version: {p.version}")

    http_scan(scan)
    scanning_log.append(
        f"Scan completed in {scan.end - scan.start:.2f} seconds.")
    logger.info(f"Scan completed in {scan.end - scan.start:.2f} seconds.")
    save_scan_to_json(scan)

    with open("scan_log.txt", "w") as f:
        f.write("\n".join(scanning_log))


################################################################################
# Routes

@app.get("/", response_class=HTMLResponse, tags=["UI"], description="Web UI for the NetEnum application")
async def home(request: Request):
    def block_home():
        return templates.TemplateResponse("index.html", {"request": request})
    return await run_in_threadpool(block_home)


@app.get(
    path="/health",
    response_class=JSONResponse,
    tags=["Healthcheck"],
    summary="Health check",
    description="Health check endpoint",
    responses={200: {
        "description": "API is running",
        "content": {"application/json": {"example": {"status": "API is running"}}},
    }, })
def read_root():
    return {"status": "API is running"}


@app.get(
    path="/state",
    response_class=JSONResponse,
    tags=["State"],
    summary="Get current scan state",
    description="Get the current state of the network scan",
)
async def get_state():
    def block_get_state():
        global state
        try:
            return state
        except Exception as e:
            logger.error(f"Error getting state: {e}")
            return {"scanning": False, "current_host": None}
    return await run_in_threadpool(block_get_state)


@app.get(
    path="/networks",
    response_class=JSONResponse,
    tags=["Networks"],
    summary="List available networks",
    description="List available networks for scanning"
)
async def list_networks():
    """
    Get list of available network interfaces and routes.

    Returns:
        dict: Contains 'interfaces' and 'routes' lists with network information
    """
    def block_list_networks():
        try:
            result = safe_run_command(["nmap", "--iflist"])

            interfaces = []
            routes = []
            parsing_interfaces = False
            parsing_routes = False

            for line in result.stdout.splitlines():
                line = line.strip()

                # Detect which section we're in
                if "INTERFACES" in line:
                    parsing_interfaces = True
                    parsing_routes = False
                    continue
                elif "ROUTES" in line:
                    parsing_interfaces = False
                    parsing_routes = True
                    continue

                # Skip header lines
                if "DEV" in line or "DST/MASK" in line or not line:
                    continue

                # Parse interface information
                if parsing_interfaces:
                    parts = line.split()
                    if len(parts) >= 6:  # Ensure we have enough parts
                        interface_info = {
                            "interface": parts[0],
                            "short_name": parts[1].strip("()"),
                            "cidr": parts[2],
                            "type": parts[3],
                            "status": parts[4] == "up",
                            "mtu": int(parts[5]) if parts[5].isdigit() else None,
                            "mac": parts[6] if len(parts) > 6 else None
                        }
                        interfaces.append(interface_info)

                # Parse route information
                elif parsing_routes:
                    parts = line.split()
                    if len(parts) >= 3:  # Ensure we have enough parts
                        route_info = {
                            "network": parts[0],
                            "interface": parts[1],
                            "metric": int(parts[2]) if parts[2].isdigit() else 0,
                            "gateway": parts[3] if len(parts) > 3 else None
                        }
                        routes.append(route_info)

            return {
                "interfaces": interfaces,
                "routes": routes,
                "available_networks": [r["network"] for r in routes if r["network"] != "0.0.0.0/0"]
            }

        except Exception as e:
            logger.error(f"Error listing networks: {e}")
            return {"interfaces": [], "routes": [], "available_networks": []}

    return await run_in_threadpool(block_list_networks)


@app.post(
    path="/scan",
    response_class=StreamingResponse,
    tags=["Scan"],
    summary="Scan a network for hosts and open ports",
    description="Scan a network for hosts and open ports using Nmap. Provide a network CIDR in the request body.",
    responses={
        200: {
            "description": "Scan log stream",
            "content": {"text/plain": {}},
        },
        400: {
            "description": "Invalid network CIDR",
            "content": {"application/json": {"example": {"error": "Invalid network CIDR", "format": "x.x.x.x/x"}}},
        },
        500: {
            "description": "Internal server error",
            "content": {"application/json": {"example": {"error": "Failed to start scan"}}},
        }
    },
)
async def scan_endpoint(scan_input: ScanInput):
    """
    Start a network scan and stream the log output.

    Args:
        scan_input: Network CIDR to scan

    Returns:
        StreamingResponse of scan logs
    """
    # Validate input
    if not scan_input.network:
        raise HTTPException(status_code=400, detail="Network CIDR required")

    try:
        network = validate_cidr(scan_input.network)
        logger.info(f"Starting scan on validated network: {network}")
    except HTTPException as e:
        logger.error(f"Invalid network CIDR: {scan_input.network}")
        raise HTTPException(
            status_code=400,
            detail={"error": "Invalid network CIDR", "format": "x.x.x.x/x"}
        )

    # Create a queue for thread-safe log streaming
    log_queue = Queue()
    log_queue.put(f"Initiating scan of {network}...\n")

    # Custom log handler to capture logs
    class QueueHandler(logging.Handler):
        def emit(self, record):
            log_entry = self.format(record)
            log_queue.put(f"{log_entry}\n")

    # Setup logging
    queue_handler = QueueHandler()
    queue_handler.setFormatter(logging.Formatter(
        '%(asctime)s [%(levelname)s] %(message)s'))
    logger.addHandler(queue_handler)

    async def stream_logs():
        """Generate log entries as they become available"""
        try:
            # Start scan in background
            scan_thread = threading.Thread(
                target=run_scan,
                args=(str(network),),
                daemon=True
            )
            scan_thread.start()

            # Stream logs while scan is running
            while scan_thread.is_alive() or not log_queue.empty():
                try:
                    # Non-blocking to allow checking if thread is still alive
                    log_entry = log_queue.get(block=True, timeout=0.5)
                    yield log_entry
                except Exception:
                    # No new logs, continue checking
                    await asyncio.sleep(0.1)
                    continue

            # Final message when scan completes
            yield "Scan complete. Results saved to database.\n"
        finally:
            # Clean up
            logger.removeHandler(queue_handler)
            # Release the thread
            scan_thread.join()

    return StreamingResponse(
        stream_logs(),
        media_type="text/plain",
        headers={
            "Content-Disposition": f"attachment; filename=scan_log_{int(time.time())}.txt"}
    )


@app.get(
    path="/graph",
    response_class=JSONResponse,
    tags=["Graph"],
    summary="Get network graph data",
    description="Get network graph data for D3 from the latest scan results",
    responses={
        200: {
            "description": "Network graph data",
            "content": {"application/json": {"example": {"nodes": [], "links": []}}},
        },
        404: {
            "description": "No scan results found",
            "content": {"application/json": {"example": {"error": "No scan results found"}}},
        },
    },
)
async def data():
    def block_data():
        if not os.path.exists("scan_results.json"):
            return {"nodes": [], "links": []}
        with open("scan_results.json") as f:
            data = json.load(f)
        nodes, links = [], []
        for host in data["hosts"]:
            nodes.append(
                {"id": host["ip"], "type": "host", **host, "group": 1})
            for port in host.get("open_ports", []):
                pid = f"{host['ip'].split('.')[-1]}_{port['port']}"
                nodes.append(
                    {"id": pid, "name": port["port"], "host": host['ip'], "type": "port", **port, "group": 2})
                links.append({"source": host["ip"], "target": pid, "value": 1})
        # Find default gateway from routes
        gateway = None
        try:
            # Get routes directly instead of using the async function
            result = safe_run_command(["nmap", "--iflist"])

            # Parse the output to find the default gateway
            parsing_routes = False

            for line in result.stdout.splitlines():
                if "ROUTES" in line:
                    parsing_routes = True
                    continue

                if parsing_routes and "0.0.0.0/0" in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        gateway = parts[3]  # Gateway IP is the 4th field
                        logger.info(f"Default gateway found: {gateway}")
                        break

            if not gateway:
                # Default to network part of first host + .1
                if data["hosts"]:
                    first_ip = data["hosts"][0]["ip"]
                    ip_parts = first_ip.split('.')
                    gateway = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1"
                    logger.info(f"Using assumed gateway: {gateway}")

        except Exception as e:
            logger.error(f"Error finding gateway: {e}")
            # If gateway detection fails, add gateway node only if we have hosts
            if data["hosts"]:
                first_ip = data["hosts"][0]["ip"]
                ip_parts = first_ip.split('.')
                gateway = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1"

        # If gateway host in not in the nodes list, add it
        if gateway and gateway not in [n["id"] for n in nodes]:
            nodes.append({"id": gateway, "host": gateway, "ip": gateway,
                         "type": "host", "hostname": "Gateway", "group": 0})

        for host in data["hosts"]:
            if host["ip"] != gateway:
                links.append(
                    {"source": gateway, "target": host["ip"], "value": 1})
        return {"nodes": nodes, "links": links}
    return await run_in_threadpool(block_data)


@app.get(
    path="/download",
    response_class=StreamingResponse,
    tags=["Download"],
    summary="Download scan results",
    description="Download the latest scan results as a JSON file. Returns 404 if no scan has been performed.",
    responses={
        200: {
            "description": "JSON file containing scan results",
            "content": {"application/json": {}},
        },
        404: {
            "description": "No scan results found",
            "content": {"application/json": {"example": {"error": "No scan results found"}}},
        },
    },
)
async def download():
    """Download the latest network scan results as a JSON file."""
    def block_download():
        if not os.path.exists("scan_results.json"):
            logger.warning("Download request failed: No scan results found")
            raise HTTPException(
                status_code=404, detail="No scan results found")

        def iterfile():
            with open("scan_results.json", mode="rb") as file_like:
                yield from file_like

        filename = f"netenum_scan_{int(time.time())}.json"
        headers = {
            'Content-Disposition': f'attachment; filename="{filename}"',
            'Access-Control-Expose-Headers': 'Content-Disposition'
        }

        logger.info(f"Sending scan results download as {filename}")
        return StreamingResponse(
            iterfile(),
            media_type="application/json",
            headers=headers
        )

    return await run_in_threadpool(block_download)


if __name__ == "__main__":

    # Check if running root
    if os.geteuid() != 0:
        logger.error("This script must be run as root")
        exit(1)

    uvicorn.run("main:app", host="0.0.0.0", port=8000,
                server_header=False, workers=4)

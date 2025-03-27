import asyncio
from collections import defaultdict, deque
from time import time

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.status import HTTP_429_TOO_MANY_REQUESTS


class RateLimiterMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_requests: int, window_seconds: int):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(deque)
        self.lock = asyncio.Lock()

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host
        current_time = time()

        async with self.lock:
            request_times = self.requests[client_ip]

            while request_times and current_time - request_times[0] > self.window_seconds:
                request_times.popleft()

            if len(request_times) >= self.max_requests:
                retry_after = self.window_seconds - \
                    (current_time - request_times[0])
                return JSONResponse(
                    {
                        "error": "Rate limit exceeded",
                        "detail": f"Limit of {self.max_requests} {'requests' if self.max_requests > 1 else 'request'} per {self.window_seconds} {'seconds' if self.window_seconds > 1 else 'second'}",
                        "retry_after": round(retry_after, 2),
                    },
                    status_code=HTTP_429_TOO_MANY_REQUESTS,
                )

            request_times.append(current_time)

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(self.max_requests)
        response.headers["X-RateLimit-Remaining"] = str(
            self.max_requests - len(self.requests[client_ip])
        )
        response.headers["X-RateLimit-Reset"] = str(
            round(self.window_seconds -
                  (current_time - self.requests[client_ip][0]), 2)
        )
        return response

import hmac
import logging
import re
import time
from typing import Dict, List, Optional, Set, Union

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)

class TokenAuthMiddleware(BaseHTTPMiddleware):
  def __init__(
    self, 
    app, 
    token: Union[None, str, List[str], Set[str], Dict[str, str]],
    exclude_paths: Optional[List[str]] = None,
    token_expiry: Optional[Dict[str, int]] = None,
  ):
    super().__init__(app)
    
    # Convert token to a set of valid tokens
    if isinstance(token, str):
      self.tokens = {token}
    elif isinstance(token, dict):
      self.tokens = set(token.values())
    elif token is None:
      self.tokens = set()
    else:
      self.tokens = set(token)
      
    self.exclude_paths = exclude_paths or []
    self.token_expiry = token_expiry or {}
    
  def _is_path_excluded(self, path: str) -> bool:
    return any(path.startswith(excluded) for excluded in self.exclude_paths)
  
  def _is_token_valid(self, token: str) -> bool:
    # Check expiry
    if token in self.token_expiry and self.token_expiry[token] < time.time():
      return False
      
    # Use constant-time comparison to prevent timing attacks
    return any(hmac.compare_digest(token, valid_token) for valid_token in self.tokens)
    
  async def dispatch(self, request, call_next):
    if self.tokens == set():
      return await call_next(request)
    
    # Skip authentication for excluded paths
    if self._is_path_excluded(request.url.path):
      return await call_next(request)
      
    auth_header = request.headers.get('Authorization')
    
    if not auth_header or not auth_header.startswith('Bearer '):
      logger.warning(f"Authentication failed: IP: {request.client.host}")
      return JSONResponse(
        status_code=401, 
        content={"error": "Unauthorized", "detail": "Invalid or missing Authorization header"}
      )
      
    token = auth_header[7:]  # Remove 'Bearer ' prefix
      
    if not self._is_token_valid(token):
      logger.warning(f"Authentication failed: Invalid token - IP: {request.client.host}")
      return JSONResponse(
        status_code=401, 
        content={"error": "Unauthorized", "detail": "Invalid token"}
      )
      
    return await call_next(request)
  
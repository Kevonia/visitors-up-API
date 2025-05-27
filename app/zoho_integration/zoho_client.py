# zoho_integration/zoho_client.py
import requests
from fastapi import HTTPException, status
from app.config.config import settings
from app.logging_config import logger
class ZohoClient:
    def __init__(self):
        self.access_token = settings.access_token
        self.zoho_api_url = settings.zoho_api_url

    def refresh_access_token(self):
        url = "https://accounts.zoho.com/oauth/v2/token"
        payload = {
            "refresh_token": settings.refresh_token,
            "client_id": settings.client_id,
            "client_secret": settings.client_secret,
            "grant_type": "refresh_token"
        }
        response = requests.post(url, data=payload)
        if response.status_code == 200:
            self.access_token = response.json()["access_token"]
        else:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Failed to refresh access token")

    def make_request(self, endpoint, method="GET", data=None):
        headers = {
            "Authorization": f"Zoho-oauthtoken {self.access_token}",
            "Content-Type": "application/json"
        }
        url = f"{self.zoho_api_url}/{endpoint}"
        logger.info(f"API endpoint:{url}")
        response = requests.request(method, url, headers=headers, json=data)

        if response.status_code == 401:  # Token expired
            self.refresh_access_token()
            headers["Authorization"] = f"Zoho-oauthtoken {self.access_token}"
            response = requests.request(method, url, headers=headers, json=data)

        if response.status_code not in [200, 201]:
            raise HTTPException(status_code=response.status_code, detail=response.json())

        return response.json()
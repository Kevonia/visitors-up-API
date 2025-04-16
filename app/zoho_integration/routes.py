# app/zoho_integration/routes.py
import logging
from fastapi import APIRouter, Depends, HTTPException, status
from aiocache import cached
from app.config.auth import get_current_user, User
from app.config.config import settings
from app.zoho_integration.zoho_client import ZohoClient
from app.logging_config import logger

router = APIRouter()
zoho_client = ZohoClient()

# Helper function to log errors


def log_error(error: Exception, endpoint: str):
    logger.error(f"Error in {endpoint}: {str(error)}")


# Protected routes with authentication and caching
cache_timer = 3600


@router.get("/invoices")
@cached(ttl=cache_timer)  # Cache response for 60 seconds
async def get_invoices():
    """Get all invoices from Zoho Invoice"""
    try:
        logger.info(f"Fetching all invoices for user:")
        return zoho_client.make_request("invoices")
    except Exception as e:
        log_error(e, "get_invoices")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch invoices",
        )


@router.get("/invoices/{invoice_id}")
@cached(ttl=cache_timer)
async def get_invoice(invoice_id: str, ):
    """Get a specific invoice by ID"""
    try:
        logger.info(f"Fetching invoice {invoice_id} for user:")
        return zoho_client.make_request(f"invoices/{invoice_id}")
    except Exception as e:
        log_error(e, "get_invoice")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch invoice with ID {invoice_id}",
        )


@router.post("/invoices")
async def create_invoice(invoice_data: dict):
    """Create a new invoice in Zoho Invoice"""
    try:
        logger.info(f"Creating a new invoice for user: ")
        return zoho_client.make_request("invoices", method="POST", data=invoice_data)
    except Exception as e:
        log_error(e, "create_invoice")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create invoice",
        )


@router.put("/invoices/{invoice_id}")
async def update_invoice(invoice_id: str, invoice_data: dict, ):
    """Update an existing invoice in Zoho Invoice"""
    try:
        logger.info(f"Updating invoice {invoice_id} for user: ")
        return zoho_client.make_request(f"invoices/{invoice_id}", method="PUT", data=invoice_data)
    except Exception as e:
        log_error(e, "update_invoice")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update invoice with ID {invoice_id}",
        )


@router.delete("/invoices/{invoice_id}")
async def delete_invoice(invoice_id: str):
    """Delete an invoice from Zoho Invoice"""
    try:
        logger.info(f"Deleting invoice {invoice_id} for user: ")
        return zoho_client.make_request(f"invoices/{invoice_id}", method="DELETE")
    except Exception as e:
        log_error(e, "delete_invoice")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete invoice with ID {invoice_id}",
        )


# User
@router.get("/users")
async def get_users():
    """Get all User from Zoho Invoice"""
    try:
        logger.info(f"Fetching all User for Zoho")
        return zoho_client.make_request("users")
    except Exception as e:
        log_error(e, "get_users")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch users",
        )
 

#Contact
@router.get("/contacts")
async def get_contacts():
    """Get all Contacts from Zoho Invoice"""
    try:
        logger.info(f"Fetching all Contacts for Zoho")
        return zoho_client.make_request("contacts")
    except Exception as e:
        log_error(e, "get_contacts")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch contacts",
        )
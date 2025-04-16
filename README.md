# FastAPI Backend Application

A robust backend API built with FastAPI for managing users, residents, visitors, roles, permissions, and more.

## Features

- **User Management**: Create, read, update, and delete user accounts
- **Role-Based Access Control**: Manage roles and permissions
- **Resident Management**: Handle resident information
- **Visitor Tracking**: Manage visitor records and allowlists
- **Authentication**: Secure API endpoints
- **Performance Monitoring**: Process time tracking middleware
- **CORS Support**: Configured for cross-origin requests
- **Logging**: Comprehensive logging configuration
- **Zoho Integration**: (Commented out but available for extension)

## API Endpoints

The API is organized into the following routes:

- `/api/v1/auth` - Authentication endpoints
- `/api/v1/user` - User management
- `/api/v1/resident` - Resident management
- `/api/v1/allow-list` - Allowlist management
- `/api/v1/role` - Role management
- `/api/v1/permission` - Permission management
- `/api/v1/visitor` - Visitor management
- `/api/v1/user/visitor` - User-visitor relationships

## Getting Started

### Prerequisites

- Python 3.7+
- Pipenv or pip
- (List any other dependencies your project might have)

### Installation

1. Clone the repository:
   ```bash
   git clone [repository-url]
   cd [project-directory]
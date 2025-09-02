# JWT Authentication with Django REST Framework

## 📌 Overview

This project demonstrates **JWT (JSON Web Token) Authentication**
implementation using **Django REST Framework (DRF)** and **SimpleJWT**.

It includes: - User Registration - JWT-based Login (Access & Refresh
tokens) - Token Refresh Endpoint - Secure API access using JWT

------------------------------------------------------------------------

## ⚙️ Installation & Setup

### 1. Clone the Repository

``` bash
git clone <https://github.com/AlokKumar-04/JWTAuthentication>
cd <JsonWebToken>
```

### 2. Create Virtual Environment & Activate

``` bash
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
```

### 4. Apply Migrations

``` bash
python manage.py migrate
```

### 5. Create Superuser (Optional)

``` bash
python manage.py createsuperuser
```

### 6. Run the Development Server

``` bash
python manage.py runserver
```

------------------------------------------------------------------------

## 🔐 JWT Endpoints

  Endpoint                Method   Description
  ----------------------- -------- -----------------------------
  `/api/token/`           POST     Get Access & Refresh tokens
  `/api/token/refresh/`   POST     Refresh Access token
  `/api/register/`        POST     User Registration

------------------------------------------------------------------------

## 🛠️ Example Requests

### Get JWT Token

``` bash
POST /api/token/
{
    "username": "yourusername",
    "password": "yourpassword"
}
```

Response:

``` json
{
    "refresh": "your-refresh-token",
    "access": "your-access-token"
}
```

### Refresh Token

``` bash
POST /api/token/refresh/
{
    "refresh": "your-refresh-token"
}
```

------------------------------------------------------------------------

## ✅ Features

-   JWT Authentication using **SimpleJWT**
-   Secure endpoints
-   Token refresh mechanism
-   User registration

------------------------------------------------------------------------

## 🏗️ Tech Stack

-   **Python**
-   **Django**
-   **Django REST Framework**
-   **SimpleJWT**

------------------------------------------------------------------------

## 📄 License

This project is open-source. Feel free to use and modify.

------------------------------------------------------------------------

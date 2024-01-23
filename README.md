This repository contains a simple Spring Boot application demonstrating JSON Web Token (JWT) authentication. The application includes two user roles, 'ADMIN' and 'USER', with corresponding endpoints protected by Spring Security.



## Controllers

### AdminController

- Path: `/admin/admin`
- Method: `GET`
- Requires 'ROLE_ADMIN' authority.
- Returns a success response if the admin endpoint is accessed.

### UserController

- Path: `/user/useronly`
- Method: `GET`
- Requires 'ROLE_USER' authority.
- Returns a success response if the user-only endpoint is accessed.

## Security Configuration

The security configuration is defined in `SecurityConfig.java`. It includes JWT authentication, role-based access, and session management.

## Usage
Access the admin endpoint: /admin/admin with 'ROLE_ADMIN'.
Access the user-only endpoint: /user/useronly with 'ROLE_USER'.

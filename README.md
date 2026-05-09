Cyber Security Analyst Internship - 2026Intern: Muhammad Saim Ali Khan   ID: DHC-4044   Organization: DevelopersHub Corporation  
Project Overview
This repository contains the complete documentation and technical implementations completed during my 3-week Cyber Security Analyst Internship. The project focused on the security lifecycle of a User Management System, moving from vulnerability identification to advanced monitoring.   
Weekly BreakdownWeek 1: Vulnerability IdentificationFocus: Security assessment and threat identification.  
Tasks: Performed basic penetration testing to simulate common attack scenarios.   
Findings: Identified risks such as unauthorized access and parameter tampering.   
Week 2: Security RemediationFocus: Implementing active defenses and hardening the application.   
Key Implementations:Password Hashing: Integrated Bcrypt to securely hash and salt passwords before storage.   
Authorization: Implemented JWT (JSON Web Tokens) to secure API endpoints.  
Header Security: Applied Helmet.js to enforce security headers and prevent attacks like XSS. 
Week 3: Advanced Security & MonitoringFocus: Verification of fixes and establishing an audit trail.  
Key Implementations:Logging: Set up a centralized logging system using Winston to record login attempts and system errors.  
Secure Transit: Configured HTTPS for encrypted communication on port 8443.   
Audit Trail: Created a security.log file to identify unusual access patterns.  
Security Best Practices Checklist[x] All user inputs are validated and sanitized   [x] Passwords securely hashed via Bcrypt   [x] Token-based authentication (JWT) for all APIs   [x] HTTPS enabled for encrypted data transit   [x] Automated security logs maintained for monitoring   
Technical EnvironmentLanguage: Node.js   
Security Libraries: Bcrypt, JSONWebToken, Helmet, Winston   
Testing Tools: Postman, OWASP ZAP 

# Nexora Business Website

Full-stack business website using Node.js, Express and PostgreSQL.

## Features

- Responsive business website
- User registration and login
- Administrator dashboard
- Contact form
- PostgreSQL database
- Password hashing
- Session authentication
- CSRF protection
- Rate limiting
- Security headers

## Requirements

- Node.js 22+
- PostgreSQL
- npm

## Local installation

1. Install Node.js and PostgreSQL.
2. Copy .env.example to .env.
3. Configure DATABASE_URL.
4. Generate SESSION_SECRET and CSRF_SECRET.
5. Run npm install.
6. Run npm start.

## Create administrator

Set these environment variables:

ADMIN_NAME
ADMIN_EMAIL
ADMIN_PASSWORD

Run:

npm run create-admin

Remove ADMIN_PASSWORD after setup.

## Start application

npm start

Open http://localhost:3000

## Deployment

Push the project to a private GitHub repository.

Connect the repository to Render using render.yaml.

Never commit .env or database credentials.

## Important

The administrator account must be created separately.
Never expose administrator credentials.
Use managed PostgreSQL backups.
Upgrade the database before production use.
Run security and functional tests before accepting real customers.

# [RUSO](https://rusonow.com) Backend API

Secure Express + MongoDB Atlas REST API for the **RUSO** shop — handles live inventory, cart checkout validation, stock reservation, and admin management.

## Features & Security

- **Server-Side Order Computation**: All prices, subtotals, delivery fees, and order totals are recomputed directly from the database to prevent client tampering.
- **Atomic Stock Reservation**: Prevents race conditions and double-orders when stock is low.
- **Brute-force & Rate Limiting**: Dedicated rate limits for general API requests, order placement, and admin authentication.
- **Strict Whitelist & Mass-Assignment Protection**: Products can only be modified through validated whitelist attributes.
- **Security Headers & CORS**: Integrated with `helmet` and restricted CORS origins.
- **Constant-Time Admin Auth**: `crypto.timingSafeEqual` prevents timing attacks on admin endpoints.

---

## API Endpoints

### Public Endpoints
- `GET /` — API health check & uptime
- `GET /api/products` — List all products with current live stock
- `POST /api/orders` — Submit customer order (validates items, verifies payment TrxID, atomically decrements stock)

### Admin Endpoints (Require `x-admin-password` header)
- `POST /api/admin/login` — Verify admin credentials
- `POST /api/products` — Create new product
- `PUT /api/products/:id` — Update product details, price, or stock
- `DELETE /api/products/:id` — Delete a product
- `GET /api/orders` — List all customer orders
- `PUT /api/orders/:id` — Update order status (`Pending confirmation`, `Confirmed`, `Shipped`, `Delivered`, `Cancelled`)

---

## Local Development Setup

1. Open `ruso-backend` directory in your terminal:
   ```bash
   cd ruso-backend
   npm install
   ```
2. Create your `.env` file from the template:
   ```bash
   cp .env.example .env
   ```
3. Edit `.env` and fill in:
   - `MONGODB_URI`: Your MongoDB Atlas connection string.
   - `ADMIN_PASSWORD`: A strong random password (min 12 characters).
   - `ALLOWED_ORIGINS`: Comma-separated list of allowed origins (e.g. `http://127.0.0.1:5500,http://localhost:5500`).
4. Start the server:
   ```bash
   npm start
   ```
   The backend will run on `http://localhost:4000`.

---

## Production Deployment (Render.com)

1. Create a new GitHub repository for `ruso-backend` and push the backend code:
   ```bash
   git init
   git add .
   git commit -m "Initial RUSO backend commit"
   git branch -M main
   git remote add origin https://github.com/<your-username>/ruso-backend.git
   git push -u origin main
   ```
2. Log into [Render.com](https://render.com) and click **New +** → **Web Service**.
3. Connect your `ruso-backend` repository.
4. Settings:
   - **Environment**: Node
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
5. In **Environment Variables**, configure:
   - `MONGODB_URI` = Your MongoDB Atlas connection URI
   - `ADMIN_PASSWORD` = A strong secret password
   - `ALLOWED_ORIGINS` = Your production frontend domain(s) (e.g. `https://ruso.shop,https://www.ruso.shop`)
6. Click **Deploy Web Service**.
7. **Keep Render Awake**: Set up a free HTTP monitor at [UptimeRobot.com](https://uptimerobot.com) targeting `https://<your-render-service>.onrender.com/` with a 5-minute interval so the free instance stays active.

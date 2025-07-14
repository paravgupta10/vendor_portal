# 🏢 VendorConnect – Vendor Registration Portal

**VendorConnect** is a full-stack web application that enables efficient vendor onboarding, verification, invoice tracking, and vendor management. Designed for organizations to streamline their vendor engagement, VendorConnect allows vendors to register, upload documents, and track approval statuses while giving admins the tools to review and manage applications effectively.

🔗 **Live Application:** [https://vendor-portal-929e.onrender.com](https://vendor-portal-929e.onrender.com)

---

## ✨ Features

### 🔐 Vendor Side
- Dynamic registration form with ownership-specific sections:
  - Sole Proprietor
  - Partnership
  - Limited Liability Partnership
  - Private Limited
  - Public Limited
  - Trust
  - NGO
- Upload important documents (PAN, GST, TAN, Balance Sheet etc.) to Supabase Storage
- View registration status dashboard
- Upload invoices and track their approval

### 🛡️ Admin Side
- Secure login for admins
- Admin dashboard with:
  - Vendor review and status management (Approve, Reject, Hold)
  - Invoice review with status filters
- Email notifications sent to vendors on status updates

---

## 🛠 Tech Stack

### Frontend
- HTML5, CSS3(Tailwind), JavaScript
- Jinja2 templating engine
- DataTables.js for table filtering

### Backend
- Python Flask
- Flask SQLAlchemy ORM

### Database & Storage
- Supabase PostgreSQL for structured data
- Supabase Storage for file uploads

---

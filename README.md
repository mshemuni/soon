# soon  
**Samba Group Policy Manager**

**`soon`** is a lightweight RESTful API for managing Group Policies on a `samba-ad-dc` (Active Directory Domain Controller).  
> ⚠️ This tool must be run directly on a domain controller.

---

## 🚀 Features

- Manage Samba AD Group Policies via API endpoints  
- Built with simplicity and sysadmins in mind  
- Easy setup and integration  

---

## 📦 Installation

Clone the repository:

```bash
git clone https://github.com/mshemuni/soon.git
cd soon
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## ⚙️ Configuration

Before running the project, set the following environment variables. You can add them to your `~/.bashrc` or `~/.zshrc` file:

```bash
export SoonSECRET_KEY="your_django_secret_key"
export SoonADAdmin="your_administrator_username"
export SoonADPassword="your_administrator_password"
```

- `SoonSECRET_KEY`: Used as Django’s `SECRET_KEY`.
- `SoonADAdmin`: The username for connecting to the Samba AD DC.
- `SoonADPassword`: The corresponding password for `SoonADAdmin`.

---

## 🔧 Setup

### Apply Migrations

```bash
python manage.py makemigrations
python manage.py migrate
```

### Create a Django Superuser

```bash
python manage.py createsuperuser
```

After creating the superuser, log in to the Django admin panel to edit the user and retrieve their **API Key** — you'll need this to authorize requests.

> 🔐 Note:  
> - All `GET` methods are available to any authenticated user.  
> - `POST`, `PUT`, and `DELETE` methods are restricted to users with `is_staff=True`.

---

## ▶️ Run the Server

```bash
python manage.py runserver 0.0.0.0:8000
```

# Examples

You can Also see: `http://<SERVER_IP>:<PORT>/api/v1/docs`

### ✅ **Health Check**
```bash
curl -X POST 'http://<SERVER_IP>:<PORT>/api/v1/gpo/health-check' \
  -H 'accept: application/json' \
  -H 'X-API-Key: ********************' \
  -d ''
```

---

### 📋 **Get All GPOs**
```bash
curl -X GET 'http://<SERVER_IP>:<PORT>/api/v1/gpo/' \
  -H 'accept: application/json' \
  -H 'X-API-Key: ********************'
```

---

### 🔍 **Get a Specific GPO**
```bash
curl -X GET 'http://<SERVER_IP>:<PORT>/api/v1/gpo?uuid=YOUR_GPO_UUID' \
  -H 'accept: application/json' \
  -H 'X-API-Key: ********************'
```

---

### 🧾 **Get Scripts of a GPO**
```bash
curl -X GET 'http://<SERVER_IP>:<PORT>/api/v1/gpo/scripts?uuid=YOUR_GPO_UUID' \
  -H 'accept: application/json' \
  -H 'X-API-Key: ********************'
```

---

### ➕ **Create GPO**
```bash
curl -X POST 'http://<SERVER_IP>:<PORT>/api/v1/gpo/?name=NewGPO&container=OU=TestOU,DC=domain,DC=local' \
  -H 'accept: application/json' \
  -H 'X-API-Key: ********************'
```

---

### 🔗 **Link GPO to Container**
```bash
curl -X PATCH 'http://<SERVER_IP>:<PORT>/api/v1/gpo/link?uuid=YOUR_GPO_UUID&container=OU=TestOU,DC=domain,DC=local' \
  -H 'accept: application/json' \
  -H 'X-API-Key: ********************'
```

---

### ❌ **Unlink GPO**
```bash
curl -X PATCH 'http://<SERVER_IP>:<PORT>/api/v1/gpo/unlink?uuid=YOUR_GPO_UUID&container=OU=TestOU,DC=domain,DC=local' \
  -H 'accept: application/json' \
  -H 'X-API-Key: ********************'
```

---

### 📂 **Add Script to GPO**
```bash
curl -X PATCH 'http://<SERVER_IP>:<PORT>/api/v1/gpo/script?uuid=YOUR_GPO_UUID&kind=Login&parameters=echo+hello' \
  -H 'accept: application/json' \
  -H 'X-API-Key: ********************' \
  -F 'file=@/path/to/your/script.bat'
```

---

### 🗑️ **Delete GPO**
```bash
curl -X DELETE 'http://<SERVER_IP>:<PORT>/api/v1/gpo/?uuid=YOUR_GPO_UUID' \
  -H 'accept: application/json' \
  -H 'X-API-Key: ********************'
```

---

### 🧹 **Remove Script from GPO**
```bash
curl -X DELETE 'http://<SERVER_IP>:<PORT>/api/v1/gpo/script?uuid=YOUR_GPO_UUID&kind=Login&script=0' \
  -H 'accept: application/json' \
  -H 'X-API-Key: ********************'
```

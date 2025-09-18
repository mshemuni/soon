
# soon  
**Samba Group Policy Manager**

`soon` is a lightweight RESTful API for managing Group Policies on a `samba-ad-dc` (Active Directory Domain Controller).  

> ⚠️ **Important:** This tool must be run directly on a domain controller.

---

## 🚀 Features

- Manage Samba AD Group Policies via simple API endpoints  
- Designed with sysadmins in mind — minimal setup, easy to use  
- Lightweight and extensible  

---

## 📦 Installation

Clone the repository:

```bash
git clone https://github.com/mshemuni/soon.git
cd soon
````

Install dependencies:

```bash
pip install -r requirements.txt
```

Install `osslsigncode`:

```bash
apt install osslsigncode
```

---

## ⚙️ Configuration

Before running the project, set the required environment variables.
Add these to your `~/.bashrc` or `~/.zshrc`:

```bash
export SoonSECRET_KEY="your_django_secret_key"
export SoonADAdmin="your_administrator_username"
export SoonADPassword="your_administrator_password"
export SoonKeys="/path/to/keys"
export SoonMachine="controller.domain.ext"
```

* **SoonSECRET\_KEY** → Django `SECRET_KEY`
* **SoonADAdmin** → Samba AD DC administrator username
* **SoonADPassword** → Password for `SoonADAdmin`
* **SoonKeys** → Path where SSL certificates will be stored
* **SoonMachine** → Domain controller hostname (optional)

---

## 🔧 Django Setup

Apply migrations:

```bash
python manage.py makemigrations
python manage.py migrate
```

Create a superuser:

```bash
python manage.py createsuperuser
```

After logging into the Django admin panel, edit the user and retrieve their **API Key**.
This key is required for API requests.

> 🔐 **Permissions:**
>
> * `GET` requests → Allowed for all authenticated users
> * `POST`, `PUT`, `DELETE` → Allowed only for users with `is_staff=True`

> 💡 **Tip:**
> If you’re using a virtual environment, ensure it inherits from the base environment.

---

## ▶️ Run the Server

For local development:

```bash
python manage.py runserver 0.0.0.0:8000
```

---

## ⚙️ Running as a Service

To run `soon` as a systemd service, create:

```bash
nano /usr/lib/systemd/system/soon.service
```

Paste and adjust as needed:

```
[Unit]
Description=Soon API
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=/root/soon
ExecStart=/Path/To/PythonENV/bin/python manage.py runserver 0.0.0.0:8006
Restart=always
RestartSec=5
Environment=SoonSECRET_KEY=your_django_secret_key
Environment=SoonADAdmin=your_administrator_username
Environment=SoonADPassword=your_administrator_password
Environment=SoonKeys=/path/to/keys
Environment=SoonMachine=controller.domain.ext

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
systemctl enable soon
systemctl start soon
```

> ⚠️ **Note:** This setup is intended for development only.
> For production, run `soon` behind a proper web server (e.g., Nginx or Apache).

---

## 📖 API Examples

Full API docs are available at:
`http://<SERVER_IP>:<PORT>/api/v1/docs`

---

### ✅ Health Check

```bash
curl -X POST 'http://<SERVER_IP>:<PORT>/api/v1/gpo/health-check' \
  -H 'accept: application/json' \
  -H 'X-API-Key: ********************' \
  -d ''
```

---

### 📋 List All GPOs

```bash
curl -X GET 'http://<SERVER_IP>:<PORT>/api/v1/gpo/' \
  -H 'accept: application/json' \
  -H 'X-API-Key: ********************'
```

---

### 🔍 Get a Specific GPO

```bash
curl -X GET 'http://<SERVER_IP>:<PORT>/api/v1/gpo?uuid=YOUR_GPO_UUID' \
  -H 'accept: application/json' \
  -H 'X-API-Key: ********************'
```

---

### 🧾 Get Scripts of a GPO

```bash
curl -X GET 'http://<SERVER_IP>:<PORT>/api/v1/gpo/scripts?uuid=YOUR_GPO_UUID' \
  -H 'accept: application/json' \
  -H 'X-API-Key: ********************'
```

---

### ➕ Create GPO

```bash
curl -X POST 'http://<SERVER_IP>:<PORT>/api/v1/gpo/?name=NewGPO&container=OU=TestOU,DC=domain,DC=local' \
  -H 'accept: application/json' \
  -H 'X-API-Key: ********************'
```

---

### 🔗 Link GPO to Container

```bash
curl -X PATCH 'http://<SERVER_IP>:<PORT>/api/v1/gpo/link?uuid=YOUR_GPO_UUID&container=OU=TestOU,DC=domain,DC=local' \
  -H 'accept: application/json' \
  -H 'X-API-Key: ********************'
```

---

### ❌ Unlink GPO

```bash
curl -X PATCH 'http://<SERVER_IP>:<PORT>/api/v1/gpo/unlink?uuid=YOUR_GPO_UUID&container=OU=TestOU,DC=domain,DC=local' \
  -H 'accept: application/json' \
  -H 'X-API-Key: ********************'
```

---

### 📂 Add Script to GPO

```bash
curl -X PATCH 'http://<SERVER_IP>:<PORT>/api/v1/gpo/script?uuid=YOUR_GPO_UUID&kind=Login&parameters=echo+hello' \
  -H 'accept: application/json' \
  -H 'X-API-Key: ********************' \
  -F 'file=@/path/to/your/script.bat'
```

---

### 🗑️ Delete GPO

```bash
curl -X DELETE 'http://<SERVER_IP>:<PORT>/api/v1/gpo/?uuid=YOUR_GPO_UUID' \
  -H 'accept: application/json' \
  -H 'X-API-Key: ********************'
```

---

### 🧹 Remove Script from GPO

```bash
curl -X DELETE 'http://<SERVER_IP>:<PORT>/api/v1/gpo/script?uuid=YOUR_GPO_UUID&kind=Login&script=0' \
  -H 'accept: application/json' \
  -H 'X-API-Key: ********************'
```
# File Storage Lab - UUID v1 Vulnerability Challenge

## ⚠️ Security Warning

**This application is intentionally vulnerable for educational purposes only. Do not use in production environments.**

---

## 🎯 Challenge

Find the admin's flag file by exploiting predictable UUID v1 patterns.

**How it works:** When you upload your first file, the system automatically creates an admin flag file with a UUID generated within **0.05 seconds** of your file's UUID. Both use UUID v1, which embeds a timestamp, making them predictable.

**Your task:**
1. Upload a file and note its UUID
2. Generate adjacent UUIDs around your file's UUID 
(Application allows multiple file upload, makes your job easy!!)
3. Enumerate and discover the admin's flag file
4. Download the flag

---

## 🚀 Installation

**Complete Installation from GitHub:**

1. **Clone the repository:**
   ```bash
   git clone https://github.com/harikrishnankv/file-storage-lab.git
   cd file-storage-lab
   ```

2. **Run the installation script:**
   ```bash
   chmod +x install.sh
   ./install.sh
   ```
   
   The script will automatically:
   - Check for Python 3 and install it if needed
   - Check for pip and install it if needed
   - Install all Python dependencies
   - Create required directories

3. **Start the application:**
   ```bash
   chmod +x start.sh
   ./start.sh
   ```
   
   Or manually:
   ```bash
   cd backend
   python3 app.py
   ```

Access at: **http://localhost:5002**

---

## 📚 Challenge Steps

1. **Register & Upload** - Register/login and upload a file (save the UUID)
2. **Extract Timestamp** - Parse UUID v1 timestamp from your file's UUID
3. **Enumerate UUIDs** - Generate UUIDs close to your file (±0.05 seconds)
4. **Find Flag** - Test UUIDs against `/api/files/{file_id}` to find `flag.txt`

---

## 🛠️ API Endpoints

- `POST /api/register` - Register user
- `POST /api/login` - Authenticate
- `POST /api/files/upload` - Upload file
- `GET /api/files/{file_id}` - Download file

**Hint:** There is one more endpoint that will make your job easier - find it after completing the challenge!

---

## 🔍 Built-in Tools

The web interface includes a **File Enumeration Tool** (Attack Tools section) that automatically tests adjacent UUIDs to find the flag.

---

## 📖 Technical Details

UUID v1 embeds a timestamp (60 bits), making sequentially generated UUIDs predictable. Files created within seconds have similar UUID values, enabling enumeration attacks.

---

## 👥 Credits

- **Sruthi M** - [LinkedIn](https://www.linkedin.com/in/sruthi-m-48600866/)
- **Ashiq K** - [LinkedIn](https://www.linkedin.com/in/ashiq-k-9308a328/)
- **Harikrishanan Kv** - [LinkedIn](https://www.linkedin.com/in/harikrishnan-kv-85738914a/)

---

## ⚖️ License

Educational purposes only. Vulnerabilities are intentional.

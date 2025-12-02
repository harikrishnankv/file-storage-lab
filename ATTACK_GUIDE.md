# UUID v1 Attack Guide - Finding the Admin Flag

## 🎯 Objective

Find the admin's flag file by exploiting predictable UUID v1 patterns.

---

## 📋 Quick Start

1. **Register & Login** - Create an account and log in
2. **Upload File** - Upload multiple files and note its UUIDs and behaviour in live status
3. **Find the Flag** - Use the built-in tool or manual enumeration to discover the flag file

---

## 🔍 How It Works

When you upload your **first file**, the system automatically creates an admin flag file with a UUID generated within **0.05 seconds** of your file's UUID. Both use UUID v1, which embeds a timestamp, making them predictable.

**Key Insight:** Files created within seconds have similar UUID values, enabling enumeration attacks.

---

## 🛠️ Steps : Using [UUID Sandwicher](https://github.com/ashiqrehan-21/UUID-Sandwicher) Tool (Easiest)

1. Login to your account
2. Upload 2 files (note the UUID)
3. Use [UUID Sandwicher](https://github.com/ashiqrehan-21/UUID-Sandwicher) and enumerate all possible UUIDs.
4. Use the download function endpoint to bruteforce UUIDs and find the flag that is uploaded by admin


---

## 💡 Tips

1. **Upload Multiple Files** - The application allows multiple file uploads, making enumeration easier
2. **Use the Debug Endpoint** - There's a debug endpoint that can help verify flag creation
3. **Check Response** - The flag file will have `flag.txt` in its content or filename

---

## 🎓 Learning Points

- **UUID v1 Vulnerability**: Timestamp embedding makes sequential UUIDs predictable
- **Temporal Correlation**: Files created close in time have similar UUIDs
- **Enumeration Attacks**: Predictable identifiers enable unauthorized access
- **Security Best Practice**: Use UUID v4 (random) instead of UUID v1 for sensitive identifiers

---

**Remember**: This lab demonstrates real vulnerabilities. Use this knowledge responsibly to build more secure applications.

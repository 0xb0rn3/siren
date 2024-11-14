# SIREN

<p align="center">
  <img src="https://raw.githubusercontent.com/q4n0/q4n0/master/assets/banner.png" alt="SIREN Banner">
</p>

<div align="center">
  
  [![Twitter Follow](https://img.shields.io/twitter/follow/byt3s3c?style=for-the-badge&logo=twitter)](https://twitter.com/byt3s3c)
  [![GitHub followers](https://img.shields.io/github/followers/q4n0?style=for-the-badge&logo=github)](https://github.com/q4n0)
  [![Instagram](https://img.shields.io/badge/Instagram-@onlybyhive-E4405F?style=for-the-badge&logo=instagram&logoColor=white)](https://instagram.com/onlybyhive)
  
</div>

**SIREN** (Simulated Insecure Real Environment Network) transforms standard Ubuntu/Debian servers into intentionally vulnerable systems for security research and penetration testing practice.

## ⚠️ WARNING

This tool creates an **EXTREMELY VULNERABLE** system! Use only in isolated lab environments.

## 🚀 Features

- **Web Vulnerabilities**
  - SQL Injection
  - File Upload
  - Command Injection
  - Directory Traversal

- **System Vulnerabilities**
  - Buffer Overflow Service
  - Kernel Exploits
  - SUID Binaries
  - Weak Permissions

- **Network Services**
  - Vulnerable SSH Config
  - Anonymous FTP
  - Exposed Services
  - Weak Configurations

- **Persistence Mechanisms**
  - System Backdoors
  - Hidden Users
  - Cron Jobs
  - Service Exploits

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/q4n0/siren.git

# Change directory
cd siren

# Make executable
chmod +x install.sh

# Run as root
sudo ./install.sh
```

## 💻 Requirements

- Ubuntu/Debian based system
- 4GB RAM minimum
- 20GB disk space
- Internet connection
- **ISOLATED** network environment

## 🎯 Usage

1. Run the script and select vulnerability modules
2. Configure desired options
3. Script will setup all vulnerabilities
4. Access services on configured ports

Default Access:
```bash
# Web Interface
http://TARGET/

# SSH Backdoor
ssh backdoor@TARGET
Password: password123

# MySQL Access
mysql -u root -p'password123' -h TARGET

# Vulnerable Service
nc TARGET 4444
```

## 🔧 Configuration

SIREN allows customization of:
- Kernel Vulnerabilities
- Web Vulnerabilities
- Database Security
- Network Services
- User Security
- File Permissions
- Service Security
- Persistence Mechanisms
- Rootkit Simulation

## 📝 Documentation

Detailed documentation available at:
- [Installation Guide](docs/installation.md)
- [Usage Guide](docs/usage.md)
- [Attack Scenarios](docs/attacks.md)
- [Vulnerability List](docs/vulnerabilities.md)

## 👤 Author

- **B0URN3**
- Twitter: [@byt3s3c](https://twitter.com/byt3s3c)
- Instagram: [@onlybyhive](https://instagram.com/onlybyhive)
- Website: [q4n0.com](https://q4n0.com)
- Blog: [blog.q4n0.com](http://blog.q4n0.com)

## ⚠️ Legal Disclaimer

This tool is created for educational purposes only! The author assumes no liability for any misuse or damage caused by this program.

```
SIREN is intended for:
✓ Security Research
✓ Educational Purposes
✓ Authorized Testing
✓ Lab Environments

NOT for:
✗ Production Systems
✗ Unauthorized Testing
✗ Malicious Activities
✗ Public Networks
```

## 🌟 Support

If you like this project, please give it a star ⭐ and share it with your friends!

---

<p align="center">
  <b>Created with ❤️ by b0urn3</b>
</p>


This tool is developed in **Python** with a user-friendly **Qt5 (PyQt5)** interface. It allows users to customize network packet behavior, especially useful for stress testing or educational demonstrations on network load handling.

### 🕵️‍♂️ IP Spoofing

The application offers a **strong IP spoofing engine**. You can configure each of the four octets of an IP address manually:

- Entering **`r`** will use a random number from **1 to 255**.
- A **range** like `50-100` will choose a number between 50 and 100.
- A **single number** like `168` will fix that octet to that value.


https://media.tenor.com/B64hJM7Ki1QAAAAM/pc-fire.gif

### 📦 Payload Options

You can choose the payload content mode:
- **Raw**: Sends completely random bytes.
- **Base64**: Sends Base64-encoded random data (increases entropy).

You also define a **minimum and maximum size** (in bytes). Each packet will randomly choose a size in that range, making traffic look unpredictable and realistic.

### 🔁 Threading

The tool supports multithreading. Up to **10 threads** are recommended for stable performance.

In practical tests, just **2 threads** sending packets of **50–100 bytes** were sufficient to crash a standard home router — showing how lightweight yet powerful the tool can be.

![resim](https://github.com/user-attachments/assets/387ea7ef-7f0e-4521-a944-b63a5ac11025)


## ⚠️ Legal & Ethical Notice

This tool was developed strictly for **educational, research, and authorized testing purposes** only. The author **does not condone or support** any form of illegal or malicious use of this software.

By using this tool, you agree to:

- Use it **only in environments where you have explicit permission**.
- Accept **full responsibility** for your actions.
- Understand that **unauthorized use is illegal** and could lead to serious consequences.

> **The author of this tool assumes no liability** for any misuse, damage, or legal issues caused by this software. Use it wisely and at your own risk.


## 🚀 Installation Commands

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/nzap.git
cd nzap

# 2. (Optional) Create a virtual environment
python -m venv venv
source venv/bin/activate     # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the application (as root/admin)
sudo python nzap.py          # On Linux/macOS

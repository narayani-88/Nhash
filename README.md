# nHash 🔍

nHash is a web application that helps you identify different types of cryptographic hashes. It can detect various hash types and provide information about them, including their corresponding Hashcat and John the Ripper formats.



## Features

- **Hash Identification**: Automatically identifies the type of cryptographic hash
- **Multiple Hashes**: Process multiple hashes at once (one per line)
- **Hashcat & John Formats**: Shows the corresponding hashcat mode and John the Ripper format
- **Copy to Clipboard**: Easily copy any hash with a single click
- **Session History**: Hashes are saved in your session until you clear them
- **Responsive Design**: Works on both desktop and mobile devices

## Supported Hash Types

- MD5, SHA-1, SHA-256, SHA-512
- bcrypt, Argon2, PBKDF2
- NTLM, LM hashes
- MySQL, PostgreSQL hashes
- Various Unix/Linux password hashes
- Bitcoin, Ethereum wallet hashes
- And many more...

## Installation

1. Clone the repository:
   ```bash
   git clone [your-repository-url]
   cd has-indetifier
   ```

2. Create and activate a virtual environment (recommended):
   ```bash
   python -m venv .venv
   .\.venv\Scripts\activate  # On Windows
   ```

3. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Run the application:
   ```bash
   python app.py
   ```

2. Open your web browser and navigate to:
   ```
   http://localhost:5000
   ```

3. Enter your hash(es) in the text area and click "Identify Hash"


## Acknowledgments

- Built with Flask
- Inspired by various hash identification tools
- Icons from [EmojiOne](https://www.emojione.com/)

---

🔒 **Note**: This tool is for educational and legitimate security testing purposes only. Always ensure you have proper authorization before testing any system.

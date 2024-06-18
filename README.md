# Fiq's Signature Checker

![Alt Text](/ss.png)

Hey there! 👋 This is Fiq's Signature Checker, a handy Python tool I created to make life easier for those of us who often sign PDF files digitally. Ever wondered if your digital signature is intact and valid? Well, wonder no more! This tool uses the power of `pypdf`, `asn1crypto`, and `dateutil` to examine PDF files and extract all the nifty signature details.

## How it Works

Let me walk you through how it works:

1. **File Upload**: Start by uploading your PDF file using the user-friendly interface.

2. **Signature Detection**: Once you've uploaded the file, my tool gets to work scanning the PDF for any digital signatures.

3. **Signature Information**: If there are digital signatures, I'll present you with a breakdown of each signature, showing you who signed it and when.

## How to Use

Imagine this scenario: you've been signing PDF documents left and right, and now you want to make sure those signatures are rock-solid. Here's how you can use my tool:

1. Clone the repository:

```bash
git clone https://github.com/fiqgant/fiqsign.git
```

2. Install dependencies:

```bash
streamlit run main.py
```

3. Run the tool:

```bash
git clone https://github.com/fiqgant/fiqsign.git
```

4. Upload your PDF file and let the tool work its magic.

## Dependencies
- **streamlit**: For the snazzy web application interface.
- **asn1crypto**: For diving into ASN.1 data structures.
- **dateutil**: For parsing dates and times.
- **pypdf**: For gobbling up PDF files.

## Contribution
If you're feeling adventurous, contributions are more than welcome! Feel free to open issues or pull requests.
# Contributing to the SOC & SOAR Lab

Thank you for your interest in improving and expanding this open-source cybersecurity detection and response repository.

---

## Code of Conduct & Safe Lab Guidelines

This repository contains detection engineering artifacts, SOAR playbooks, and simulated attack scripts designed solely for **defensive cybersecurity training, academic demonstration, and authorized security research**.

1. **Authorized Environments Only**: Never run offensive simulation scripts or test tools on production environments or unauthorized networks.
2. **Sanitize Data**: Ensure all IP addresses, API tokens, passwords, and private company keys are removed or sanitized before submitting pull requests.

---

## How to Contribute

1. **Fork the Repository** on GitHub.
2. **Create a Feature Branch** (`git checkout -b feature/new-playbook`).
3. **Commit Your Changes** (`git commit -m 'feat: Add Defender for Endpoint SOAR connector'`).
4. **Push to the Branch** (`git push origin feature/new-playbook`).
5. **Run the offline checks** from the repository root:
   ```bash
   python scripts/validate_lab_assets.py
   python -m unittest discover -s tests -v
   ```
6. **Open a Pull Request** and include the validation results.

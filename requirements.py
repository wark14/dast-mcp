# requirements.py
# A helper script to verify and list the installed dependencies for the AI DAST pipeline.

import sys

DEPENDENCIES = [
    "flask",
    "reportlab",
    "beautifulsoup4",
    "requests",
    "matplotlib",
    "mcp",
    "fastmcp"
]

print("Checking installed dependencies for AI DAST Agent:")
missing = []

for dep in DEPENDENCIES:
    try:
        if dep == "beautifulsoup4":
            import bs4
        else:
            __import__(dep)
        print(f"  [✓] {dep} is installed.")
    except ImportError:
        print(f"  [✗] {dep} is MISSING.")
        missing.append(dep)

if missing:
    print(f"\nWarning: The following packages are missing: {', '.join(missing)}")
    print("Please install them using: pip install -r requirements.txt")
    sys.exit(1)
else:
    print("\nAll dependencies are successfully verified.")
    sys.exit(0)

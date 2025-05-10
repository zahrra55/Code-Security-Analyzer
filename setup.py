from setuptools import setup, find_packages

setup(
    name="code-security-analyzer",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "flask",
        "flask-limiter",
        "prometheus-client",
        "transformers",
        "torch",
        "aiohttp",
        "beautifulsoup4",
        "reportlab",
        "python-magic",
        "pyyaml"
    ],
    python_requires=">=3.8",
    author="Your Name",
    author_email="your.email@example.com",
    description="A comprehensive code security analysis tool",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/code-security-analyzer",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
) 
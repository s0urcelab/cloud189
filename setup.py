from setuptools import setup

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="cloud189",
    version="<PYPI_VERSION>",
    author="s0urce",
    author_email="me@src.moe",
    description="A Python SDK for interacting with Cloud189",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/s0urcelab/cloud189",
    packages=["cloud189"],
    package_dir={"cloud189": "cloud189"},
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.9",
    install_requires=[
        "pycryptodome>=3.15.0",
        "httpx==0.28.1",
    ],
) 
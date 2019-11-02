from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="kube-hunter",
    version="0.1.0",
    author="Aqua Security",
    author_email="info@aquasec.in",
    description="Hunt for security weaknesses in Kubernetes clusters",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/aquasecurity/kube-hunter",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    python_requires=">=3.6",
)

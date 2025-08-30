from setuptools import setup, find_packages

setup(
    name="forensiq-aiagent",  # Updated name
    version="1.0.0",
    description="ForensIQ CLI Tool for automated log analysis and AI-powered threat detection.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Vaibhav M N",
    author_email="vaibhavvaibhu2005@gmail.com",
    url="https://github.com/Vaibhav2154/forensiq",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "aiohttp>=3.8.0",
        "aiofiles>=23.0.0",
        "cryptography>=41.0.0",
        "schedule>=1.2.0",
        "requests>=2.31.0",
        "motor>=3.3.0",
        "pymongo>=4.5.0",
        "python-dotenv>=1.0.0",
        "pydantic>=2.0.0",
        "rich>=13.0.0",
    ],
    entry_points={
        "console_scripts": [
            "forensiq-cli=cli_tool:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3.7",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
)

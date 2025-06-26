from setuptools import setup, find_packages

setup(
    name="ai-pentest-platform",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        'PyQt5>=5.15.0',
        'python-nmap>=0.7.1',
        'reportlab>=4.0.0',
        'SQLAlchemy>=2.0.0',
        'requests>=2.25.0',
    ],
) 
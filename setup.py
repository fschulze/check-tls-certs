from setuptools import setup
import os


README = open(os.path.abspath('README.rst')).read()
HISTORY = open(os.path.abspath('HISTORY.rst')).read()


setup(
    name='check-tls-certs',
    version='0.12.0',
    description="Check TLS certificates of domains for expiration dates and more.",
    long_description="\n\n".join([README, HISTORY]),
    url='https://github.com/fschulze/check-tls-certs',
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8"],
    install_requires=[
        'click',
        'pyOpenSSL'],
    entry_points={
        'console_scripts': ['check_tls_certs = check_tls_certs:main']},
    py_modules=['check_tls_certs'])

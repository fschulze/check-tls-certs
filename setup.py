from setuptools import setup
import os


README = open(os.path.abspath('README.rst')).read()
HISTORY = open(os.path.abspath('HISTORY.rst')).read()


setup(
    name='check-tls-certs',
    version='0.3.0',
    long_description="\n\n".join([README, HISTORY]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5"],
    install_requires=[
        'click',
        'pyOpenSSL'],
    entry_points={
        'console_scripts': ['check_tls_certs = check_tls_certs:main']},
    py_modules=['check_tls_certs'])

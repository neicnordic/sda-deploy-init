from setuptools import setup, find_packages

setup(
    name='lega_init',
    version='0.1.0',
    packages=find_packages(),
    py_modules=['lega_init'],
    include_package_data=True,
    description='LocalEGA init script generating configuration parameters such as passwords and keys.',
    author='LocalEGA Developers',
    install_requires=[
        'click>=6.7',
        'PGPy==0.4.3',
        'PyYAML',
        'cryptography',
        'PyJWT>=1.7.1'
    ],
    entry_points={
        'console_scripts': [
            'legainit=lega_init.deploy:main'
        ]
    },
)

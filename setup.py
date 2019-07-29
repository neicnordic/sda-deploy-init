from setuptools import setup, find_packages

setup(
    name='legainit',
    version='0.3.0',
    packages=find_packages(),
    py_modules=['legainit'],
    include_package_data=True,
    project_urls={
        'Source': 'https://github.com/neicnordic/LocalEGA-deploy-init',
    },
    description='LocalEGA init script generating configuration parameters such as passwords and keys.',
    author='LocalEGA Developers',
    install_requires=[
        'click>=6.7',
        'PGPy==0.4.3',
        'ruamel.yaml',
        'cryptography',
        'PyJWT>=1.7.1'
    ],
    entry_points={
        'console_scripts': [
            'legainit=lega_init.deploy:main'
        ]
    },
    platforms='any',
    classifiers=[
        'Development Status :: 5 - Production/Stable',

        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Topic :: Security :: Cryptography',

        'License :: OSI Approved :: Apache Software License',

        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
)

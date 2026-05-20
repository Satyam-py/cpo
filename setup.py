from setuptools import setup, find_packages

setup(

    name="cpo",

    version="1.0",

    packages=find_packages(),

    install_requires=[
        "colorama"
    ],

    entry_points={

        "console_scripts": [

            "cpo=cpo.main:main"
        ]
    }
)
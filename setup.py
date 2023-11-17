import setuptools
from mend_sca_cleanup_tool._version import __version__, __tool_name__, __description__

mend_name = f"mend_{__tool_name__}"

setuptools.setup(
    name=mend_name,
    entry_points={
        'console_scripts': [
            f'{mend_name}={mend_name}.{__tool_name__}:main'
        ]},
    version=__version__,
    author="Mend Professional Services",
    author_email="ps@whitesourcesoftware.com",
    description=__description__,
    url=f"https://github.com/mend-toolkit/{mend_name.replace('_', '-')}",
    license='LICENSE.txt',
    packages=setuptools.find_packages(),
    python_requires='>=3.9',
    install_requires=[line.strip() for line in open("requirements.txt").readlines()],
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    classifiers=[
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
)

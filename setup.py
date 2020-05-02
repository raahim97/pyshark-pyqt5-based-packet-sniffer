import setuptools

with open("README.md", "r") as fh:

    long_description = fh.read()

setuptools.setup(

     name='packet_sniffer',  

     version='0.1',

     author="Samyutha",

     author_email="samyutha@zilogic.com",

     description="A Pyshark and pyqt5 package to sniff packets",

     long_description=long_description,

   long_description_content_type="text/markdown",

     url="https://github.com/darkshadow-03/pyshark-pyqt5-based-packet-sniffer",

     packages=["src_code"],

     classifiers=[

         "Programming Language :: Python :: 3",

         "License :: OSI Approved :: MIT License",

         "Operating System :: OS Independent",

     ],

 )

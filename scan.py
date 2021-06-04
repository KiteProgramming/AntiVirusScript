"""

The main goal for this project is for the users to be able to upload files inside our software and detect malicious activity on those files.

"""


"""
Importing Modules

"""
import tornado.web
import tornado.ioloop

import glob
import re

import matplotlib.image as mpimg 
import matplotlib.pyplot as plt

from PIL import Image

import pywhatkit
import os

import sys

from tkinter import *
from tkinter import ttk





### Deleting all previous uploaded files.

directory = "uploadfolder"

files_in_directory = os.listdir(directory)
filtered_files = [file for file in files_in_directory if file.endswith(".txt")] #this line is not necessary it is just an example to delete certain file types

for file in files_in_directory:
	path_to_file = os.path.join(directory, file)
	os.remove(path_to_file)

### Function that asks for userinput to upload files


def exit():

    userinput = input("Type Y if you want to upload another file for scan or N to exit the program:")
    userinput = userinput.capitalize()

    if userinput == 'Y':
        upload()


    
    elif userinput == 'N':
        sys.exit(0)
    else:
        userinput = input("Type Y if you want to upload another file for scan or N to exit the program:")
        userinput = userinput.capitalize()
        while userinput != 'Y' or userinput != 'N':

            userinput = input("Type Y if you want to upload another file for scan or N to exit the program:")    
            userinput = userinput.capitalize()
            if userinput == 'Y':
                upload()
            elif userinput == 'N':
                sys.exit(0)
            else:
                userinput = input("Type Y if you want to upload another file for scan or N to exit the program:")
                userinput = userinput.capitalize()

        


"""
upload function which allows the user to upload files to be scanned

"""

def upload():
    convertion() # calling the convertion function to convert files to formats that can be checked for viruses
    class uploadHandler(tornado.web.RequestHandler):
        def get(self): # Get method
            self.render("upload.html")  # Defining which html file to render when running this file

        def post(self): # Post method            
            files = self.request.files["File"]
            for f in files:
                fh = open(f"uploadfolder/{f.filename}","wb")
                fh.write(f.body)
                fh.close()
                print(fh)
            self.write(f"http://localhost:8080/uploadfolder/{f.filename}")
            convertion() # calling the convertion function to convert files to formats that can be checked for viruses 
            checkForViruses() # calling the checkForViruses function to run the scan for our files
            exit()

            
    if (__name__ == "__main__"):

        

        
        userinput = input("Type Y if you are uploading your first file or anything else if you already uploaded your first file!!:")
        userinput = userinput.capitalize()
        if userinput == 'Y':

            app = tornado.web.Application([

            ("/" , uploadHandler),
                ("/uploadfolder/(.*)", tornado.web.StaticFileHandler, {"path" : "uploadfolder"})
            ])
        
        

        
        
            app.listen(8080)
            print('This is app.listen', app.listen)
        
            print("Listening on port 8080")
            tornado.ioloop.IOLoop.instance().start()
        else:
            print('Ready to upload another file refresh the page.')    

        


        
         



        

        

        
        







"""
Convertion Function, converts images into txt files for the purpose of correctly scanning them.

Also excel and word document files to executables.

"""

def convertion(): 

   
    
    for filename in os.listdir('uploadfolder'): 
        path = "uploadfolder/" + filename
        newpath = path + ".txt"
     

        filename = filename.lower()
        if filename.endswith(".png"):
            pywhatkit.image_to_ascii_art(path , newpath)
        elif filename.endswith(".jpg"):
            pywhatkit.image_to_ascii_art(path , newpath)
        elif filename.endswith(".xlsx"):
            os.rename(path,path+".exe")
        elif filename.endswith(".docx"):
            os.rename(path,path+".exe")                     
        else:
            continue        
      


        


        



"""

scan for viruses, function that scans for malicious content in files

"""

def checkForViruses():

    
    #print("Scanning other python Files! ") 

### If a python file contains the string virusCode in their syntax it means it is infected with viruses.

### The text virusCode is a text that is used for test purposes on python files and does not actually mean that the file is infected,

### it is just a text that we used to pass code from one python file to another in order to understand how malicious code can be spread throughout files.


######Commenting out the part where we check python files because this was just for testing purposes.

#    programs = glob.glob("uploadfolder/*.py") 
#    for p in programs:
#        thisFileInfected = False
#        file = open(p , "r")
#        lines = file.readlines()
#        file.close()

#        for line in lines:
#            if(re.search("virusCode",line)):
                #found a virus
#                print("!!!!! Virus found in file" + p)
#                thisFileInfected = True
#        if thisFileInfected == False:
#            print(p + " appears to be clean")
                    


#    print(' Scanning of python files ended ')
   
#    print()
     
### If an image when converted to ascii contains readable text in the new txt file created it means it is infected with malicious software.
### We chose the word width because it is a common programming language word used by hackers to infect pictures files with malicious content.
    print('Scanning Images')
    programs = glob.glob("uploadfolder/*.txt") 
    for p in programs:
        thisFileInfected = False
        file = open(p , "r")
        lines = file.readlines()
        file.close()

        for line in lines:
            if(re.search("width",line)):
                #found a virus
                print("!!!!! Virus found in file" + p)
                thisFileInfected = True
        if thisFileInfected == False:
            print(p + " appears to be clean")


    print('Scanning of images ended ')
    print()


    

### Any executable file could contain macro virus in it. We are converting and then checking each file that can be turned into executable.

    print('Scanning Word Files')
    programs = glob.glob("uploadfolder/*.docx.exe") 
    for p in programs:
        b = b''
        thisFileInfected = False
        file = open(p , "rb")
        byte = file.read(1)
        b = b + byte
        while byte:
            byte = file.read(1)
            b = b + byte
            
            if b == b'\\x53\\x75\\x62\\x44\\x6f\\x63\\x75\\x6d\\x65\\x6e\\x74\\x4f\\x70\\x65\\x6e\\x28\\x29':
                #found a virus
                print("!!!!! Virus found in file" + p)
                thisFileInfected = True

            elif b == b'\\x41\\x75\\x74\\x6f\\x45\\x78\\x65\\x63\\x28\\x29':
                #found a virus
                print('!!!!! Virus found in file' + p)
                thisFileInfected = True        
        if thisFileInfected == False:
            print(p + " appears to be clean")


        file.close()    
          


    print('Scanning of word files ended ')
    print()

    print('Scanning EXCEL Files')
    programs = glob.glob("uploadfolder/*.xlsx.exe") 
    for p in programs:
        b = b''
        thisFileInfected = False
        file = open(p , "rb")
        byte = file.read(1)
        b = b + byte
        while byte:
            byte = file.read(1)
            b = b + byte
            
            if b == b'\\x53\\x75\\x62\\x44\\x6f\\x63\\x75\\x6d\\x65\\x6e\\x74\\x4f\\x70\\x65\\x6e\\x28\\x29':
                #found a virus
                print("!!!!! Virus found in file" + p)
                thisFileInfected = True

            elif b == b'\\x41\\x75\\x74\\x6f\\x4f\\x70\\x65\\x6e\\x0a':
                #found a virus
                print('!!!!! Virus found in file' + p)
                thisFileInfected = True        
        if thisFileInfected == False:
            print(p + " appears to be clean")

        file.close()

    print('Scanning of EXCEL files ended ')
    print()                    
    """
    The following code makes sure that deletes all the converted word and excel documents to executables before checking the actual executables.

    This helps us avoid checking a file twice for viruses.
    
    """
    directory = "uploadfolder"

    files_in_directory = os.listdir(directory)
    filtered_files = [file for file in files_in_directory if file.endswith(".docx.exe")]
    filtered_excel_files = [file for file in files_in_directory if file.endswith(".xlsx.exe")]
    for file in filtered_files:
	    path_to_file = os.path.join(directory, file)
	    os.remove(path_to_file)

    for file in filtered_excel_files:
        path_to_file = os.path.join(directory,file)
        os.remove(path_to_file)

    print('Scanning executable Files')
    programs = glob.glob("uploadfolder/*.exe") 
    for p in programs:
        b = b''
        thisFileInfected = False
        file = open(p , "rb")
        byte = file.read(1)
        b = b + byte
        while byte:
            byte = file.read(1)
            b = b + byte
            
            if b == b'\\x53\\x75\\x62\\x44\\x6f\\x63\\x75\\x6d\\x65\\x6e\\x74\\x4f\\x70\\x65\\x6e\\x28\\x29':
                #found a virus
                print("!!!!! Virus found in file" + p)
                thisFileInfected = True

            elif b == b'\\x41\\x75\\x74\\x6f\\x45\\x78\\x65\\x63\\x28\\x29':
                #found a virus
                print('!!!!! Virus found in file' + p)
                thisFileInfected = True
            elif b == b'\\x41\\x75\\x74\\x6f\\x4f\\x70\\x65\\x6e\\x0a':
                #found a virus
                print('!!!!! Virus found in file' + p)
                thisFileInfected = True                    
        if thisFileInfected == False:
            print(p + " appears to be clean")

        file.close()

    print('Scanning of executable files ended ')
    print()            



exit()   









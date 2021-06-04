"""
Importing Modules

"""
import unittest
import os
import glob
import re

"""
Unit Testing Class

"""
class TestStringMethods(unittest.TestCase):


    ### Unit Testing that the uploaded files are uploaded on the format that we are able to check for malicious content        
    def test_format(self):
        directory = "uploadfolder"
        files_in_directory = os.listdir(directory)
        length = len(files_in_directory)
        if length == 0:
            answer = True
        else:    
            answer = False
        for file in files_in_directory:
            if file.endswith(".png") or file.endswith(".jpg") or file.endswith(".txt") or file.endswith(".docx") or file.endswith(".xlsx") or file.endswith(".exe"):
                answer = True

        self.assertEqual(answer,True)
    ### Unit Testing that the re.search module works properly and can detect signatures
    def test_detection_txtfiles(self):
        infected = False
        file = open('testfile.txt' , "r")
        lines = file.readlines()
        file.close()

        for line in lines:
            if(re.search("INFECTED",line)):
                #found a virus
                #print("!!!!! Virus found in file" )
                infected = True
        if infected == False:
            print(p + " appears to be clean")
        self.assertEqual(infected, True)
    ### Unit Testing that our script can detect macro viruses in word files and excel files
    def test_detection_exefiles(self):
        b = b''
        infected = False
        file = open('testfile.exe' , "rb")
        byte = file.read(1)
        b = b + byte
        while byte:
            byte = file.read(1)
            b = b + byte
               
              
            if b == b'\\x53\\x75\\x62\\x44\\x6f\\x63\\x75\\x6d\\x65\\x6e\\x74\\x4f\\x70\\x65\\x6e\\x28\\x29':
                #found a virus
                infected = True
            elif b == b'\\x41\\x75\\x74\\x6f\\x45\\x78\\x65\\x63\\x28\\x29':
                #found a virus
                infected = True    
            elif b == b'\\x41\\x75\\x74\\x6f\\x4f\\x70\\x65\\x6e\\x0a':
                #found a virus
                infected = True


        file.close()
        self.assertEqual(infected, True)                    

if __name__ == '__main__':
    unittest.main()
    
"""

This file will be used to write the code to add an upload feature for the users.

The main goal for this project is for the users to be able to upload files inside our software and detect malicious activity on those files.

This feature will be crucial for the completion of this project.

"""


import tornado.web
import tornado.ioloop


class uploadHandler(tornado.web.RequestHandler):
    def get(self): # Get method
        self.render("upload.html")  # Defining which html file to render when running this file.

    def post(self): # Post method
         files = self.request.files["imgFile"]
         for f in files:
             fh = open(f"uploadfolder/{f.filename}","wb")
             fh.write(f.body)
             fh.close()
         self.write(f"http://localhost:8080/uploadfolder/{f.filename}")    

if (__name__ == "__main__"):
    app = tornado.web.Application([

        ("/" , uploadHandler),
        ("/uploadfolder/(.*)", tornado.web.StaticFileHandler, {"path" : "uploadfolder"})
    ])

    app.listen(8080)
    print("Listening on port 8080")

    tornado.ioloop.IOLoop.instance().start()
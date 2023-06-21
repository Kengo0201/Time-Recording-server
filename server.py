#!/usr/bin/env python

# This is a simple web server for a time recording application.
# It's your job to extend it by adding the backend functionality to support
# recording the time in a SQL database. You will also need to support
# user access/session control. You should only need to extend this file.
# The client side code (html, javascript and css) is complete and does not
# require editing or detailed understanding.

# import the various libraries needed
import http.cookies as Cookie   # some cookie handling support
from http.server import BaseHTTPRequestHandler, HTTPServer # the heavy lifting of the web server
import urllib # some url parsing support
import json   # support for json encoding
import sys    # needed for agument handling
import time   # time support

# The following seven build_ functions return the actions that the front end client understand.
# You can return a list of these.

def build_remove_instance(id):
    """This function builds a remove_instance action that allows an
       activity instance to be removed from the index.html web page"""
    return {"type":"remove_instance","id":id}

def build_remove_activity(id):
    """This function builds a remove_activity action that allows
       an activity type to be removed from the activity.html web page"""
    return {"type":"remove_activity","id":id}

def build_response_message(code, text):
    """This function builds a message action that displays a message
       to the user on the web page. It also returns an error code."""
    return {"type":"message","code":code, "text":text}

def build_response_summary(id,period,interr,interd, ttime):
    """This function builds a summary response that contains one summary table entry."""
    return {"type":"summary","id":id, "period":period,"interrupted":interr,"interrupting":interd,"time":ttime}

def build_response_activity(id, name):
    """This function builds an activity response that contains the id and name of an activity type,"""
    return {"type":"activity", "id":id, "name":name}

def build_response_instance(id, note, timestamp):
    """This function builds an instance response that contains the id,timestamp and note"""
    return {"type":"instance", "id":id, "note":note, "timestamp":timestamp}

def build_response_redirect(where):
    """This function builds the page redirection action
       It indicates which page the client should fetch.
       If this action is used, it should be the only response provided."""
    return {"type":"redirect", "where":where}

def handle_validate(iuser, imagic):
    """Decide if the combination of user and magic is valid"""
    ## alter as required
    if (iuser == 'test') and (imagic == '1234567890'):
        return True
    else:
        return False


def handle_delete_session(iuser, imagic):
    """Remove the combination of user and magic from the data base, ending the login"""
    return

# The following handle_..._request functions are invoked by the corresponding /action?command=.. request

def handle_login_request(iuser, imagic, content):
    """A user has supplied a username (parameters['usernameinput'][0])
       and password (parameters['passwordinput'][0]) check if these are
       valid and if so, create a suitable session record in the database
       with a random magic identifier that is returned.
       Return the username, magic identifier and the response action set."""
    print(content)
    if handle_validate(iuser, imagic) == True:
        # the user is already logged in, so end the existing session.
        handle_delete_session(iuser, imagic)

    response = []
    ## alter as required
    if (1+1) == 2: ## The user is valid
        response.append(build_response_redirect('/index.html'))
        user = 'test'
        magic = '1234567890'
    else: ## The user is not valid
        response.append(build_response_message(100, 'Invalid password'))
        user = '!'
        magic = ''
    return [user, magic, response]

def handle_logout_request(iuser, imagic, parameters):
    """This code handles the selection of the logout button on the summary page (summary.html)
       You will need to ensure the end of the session is recorded in the database
       And that the session magic is revoked."""
    response = []
    ## alter as required
    response.append(build_response_redirect('/index.html'))
    user = '!'
    magic = ''
    return [user, magic, response]

def handle_summary_request(iuser, imagic, content):
    """This code handles a request for an update to the session summary values.
       You will need to extract this information from the database.
       You must return a value for all vehicle types, even when it's zero."""
    response = []
    ## alter as required
#    if handle_validate(iuser, imagic) != True:
#        response.append(build_response_redirect('/index.html'))
#    else:
    response.append(build_response_summary(1,2,3,4,4900))
    response.append(build_response_summary(3,2,3,4,1400))
    response.append(build_response_summary(4,2,3,4,37))
    user = ''
    magic = ''
    return [user, magic, response]


def handle_get_activities_request(iuser, imagic):
    """This code handles a request for an update to the session summary values.
       You will need to extract this information from the database.
       You must return a value for all vehicle types, even when it's zero."""
    response = []
    ## alter as required
#    if handle_validate(iuser, imagic) != True:
#        response.append(build_response_redirect('/index.html'))
#    else:
    response.append(build_response_activity(1,'CM50267 Lecture'))
    response.append(build_response_activity(2,'CM50267 Lab'))
    response.append(build_response_activity(3,'CM50267 Prep'))
    response.append(build_response_activity(4,'CM50267 Office Hours'))
    user = ''
    magic = ''
    return [user, magic, response]

def handle_get_instances_request(iuser, imagic):
    """This code handles a request for an update to the session summary values.
       You will need to extract this information from the database.
       You must return a value for all vehicle types, even when it's zero."""
    response = []
    ## alter as required
#    if handle_validate(iuser, imagic) != True:
#        response.append(build_response_redirect('/index.html'))
#    else:
    response.append(build_response_instance(1,'',time.time()))
    user = ''
    magic = ''
    return [user, magic, response]

def handle_begin_instance_request(iuser, imagic, content):
    """This code handles a request for an update to the session summary values.
       You will need to extract this information from the database.
       You must return a value for all vehicle types, even when it's zero."""
    response = []
    response.append(build_response_message(0, "Activity Started"))
    response.append(build_response_instance(content["id"],content['note'],time.time()))
    ## alter as required
#    if handle_validate(iuser, imagic) != True:
#        response.append(build_response_redirect('/index.html'))
#    else:
    #response.append(build_response_instance(1,'', time.time()))
    user = ''
    magic = ''
    return [user, magic, response]

def handle_end_instance_request(iuser, imagic, content):
    """This code handles a request for an update to the session summary values.
       You will need to extract this information from the database.
       You must return a value for all vehicle types, even when it's zero."""
    response = []
    response.append(build_response_message(0, "Activity Ended"))
    response.append(build_remove_instance(content["id"]))
    ## alter as required
#    if handle_validate(iuser, imagic) != True:
#        response.append(build_response_redirect('/index.html'))
#    else:
    #response.append(build_response_instance(1,'',time.time()))
    user = ''
    magic = ''
    return [user, magic, response]

def handle_add_activity_request(iuser, imagic, content):
    """This code handles a request for an update to the session summary values.
       You will need to extract this information from the database.
       You must return a value for all vehicle types, even when it's zero."""
    response = []
    response.append(build_response_message(0, "Activity Type Added"))
    response.append(build_response_activity(8,content['name']))
    ## alter as required
#    if handle_validate(iuser, imagic) != True:
#        response.append(build_response_redirect('/index.html'))
#    else:
    #response.append(build_response_instance(1,'', time.time()))
    user = ''
    magic = ''
    return [user, magic, response]

def handle_delete_activity_request(iuser, imagic, content):
    """This code handles a request for an update to the session summary values.
       You will need to extract this information from the database.
       You must return a value for all vehicle types, even when it's zero."""
    response = []
    response.append(build_response_message(0, "Deleted Activity Type"))
    response.append(build_remove_activity(content["id"]))
    ## alter as required
#    if handle_validate(iuser, imagic) != True:
#        response.append(build_response_redirect('/index.html'))
#    else:
    #response.append(build_response_instance(1,'',time.time()))
    user = ''
    magic = ''
    return [user, magic, response]


# HTTPRequestHandler class
class myHTTPServer_RequestHandler(BaseHTTPRequestHandler):

    # POST This function responds to GET requests to the web server.
    def do_POST(self):

        # The set_cookies function adds/updates two cookies returned with a webpage.
        # These identify the user who is logged in. The first parameter identifies the user
        # and the second should be used to verify the login session.
        def set_cookies(x, user, magic):
            ucookie = Cookie.SimpleCookie()
            ucookie['u_cookie'] = user
            x.send_header("Set-Cookie", ucookie.output(header='', sep=''))
            mcookie = Cookie.SimpleCookie()
            mcookie['m_cookie'] = magic
            x.send_header("Set-Cookie", mcookie.output(header='', sep=''))

        # The get_cookies function returns the values of the user and magic cookies if they exist
        # it returns empty strings if they do not.
        def get_cookies(source):
            rcookies = Cookie.SimpleCookie(source.headers.get('Cookie'))
            user = ''
            magic = ''
            for keyc, valuec in rcookies.items():
                if keyc == 'u_cookie':
                    user = valuec.value
                if keyc == 'm_cookie':
                    magic = valuec.value
            return [user, magic]

        # Fetch the cookies that arrived with the GET request
        # The identify the user session.
        user_magic = get_cookies(self)

        print(user_magic)

        # Parse the GET request to identify the file requested and the parameters
        parsed_path = urllib.parse.urlparse(self.path)

        # Decided what to do based on the file requested.

        # The special file 'action' is not a real file, it indicates an action
        # we wish the server to execute.
        if parsed_path.path == '/action':
            self.send_response(200) #respond that this is a valid page request

            # extract the content from the POST request.
            # This are passed to the handlers.
            length =  int(self.headers.get('Content-Length'))
            scontent = self.rfile.read(length).decode('ascii')
            print(scontent)
            if length > 0 :
              content = json.loads(scontent)
            else:
              content = []

            # deal with get parameters
            parameters = urllib.parse.parse_qs(parsed_path.query)

            if 'command' in parameters:
                # check if one of the parameters was 'command'
                # If it is, identify which command and call the appropriate handler function.
                if parameters['command'][0] == 'login':
                    [user, magic, response] = handle_login_request(user_magic[0], user_magic[1], content)
                    #The result of a login attempt will be to set the cookies to identify the session.
                    set_cookies(self, user, magic)
                elif parameters['command'][0] == 'logout':
                    [user, magic, response] = handle_logout_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'get_activities':
                    [user, magic, response] = handle_get_activities_request(user_magic[0], user_magic[1])
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'get_instances':
                    [user, magic, response] = handle_get_instances_request(user_magic[0], user_magic[1])
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'begin_instance':
                    [user, magic, response] = handle_begin_instance_request(user_magic[0], user_magic[1],content)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'end_instance':
                    [user, magic, response] = handle_end_instance_request(user_magic[0], user_magic[1],content)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'add_activity':
                    [user, magic, response] = handle_add_activity_request(user_magic[0], user_magic[1],content)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'delete_activity':
                    [user, magic, response] = handle_delete_activity_request(user_magic[0], user_magic[1],content)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'fetch_summary':
                    [user, magic, response] = handle_summary_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                else:
                    # The command was not recognised, report that to the user.
                    response = []
                    response.append(build_response_refill('message', 901, 'Internal Error: Command not recognised.'))

            else:
                # There was no command present, report that to the user.
                response = []
                response.append(build_response_refill('message', 902,'Internal Error: Command not found.'))

            text = json.dumps(response)
            print(text)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(bytes(text, 'utf-8'))

        else:
            # A file that does n't fit one of the patterns above was requested.
            self.send_response(404)
            self.end_headers()
        return

   # GET This function responds to GET requests to the web server.
    def do_GET(self):

        # Parse the GET request to identify the file requested and the parameters
        parsed_path = urllib.parse.urlparse(self.path)

        # Decided what to do based on the file requested.

        # Return a CSS (Cascading Style Sheet) file.
        # These tell the web client how the page should appear.
        if self.path.startswith('/css'):
            self.send_response(200)
            self.send_header('Content-type', 'text/css')
            self.end_headers()
            with open('.'+self.path, 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # Return a Javascript file.
        # These contain code that the web client can execute.
        elif self.path.startswith('/js'):
            self.send_response(200)
            self.send_header('Content-type', 'text/js')
            self.end_headers()
            with open('.'+self.path, 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # A special case of '/' means return the index.html (homepage)
        # of a website
        elif parsed_path.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            with open('./index.html', 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # Return html pages.
        elif parsed_path.path.endswith('.html'):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            with open('.'+parsed_path.path, 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        else:
            # A file that does n't fit one of the patterns above was requested.
            self.send_response(404)
            self.end_headers()
        return

def run():
    """This is the entry point function to this code."""
    print('starting server...')
    ## You can add any extra start up code here
    # Server settings
    # Choose port 8081 over port 80, which is normally used for a http server
    if(len(sys.argv)<2): # Check we were given both the script name and a port number
        print("Port argument not provided.")
        return
    server_address = ('127.0.0.1', int(sys.argv[1]))
    httpd = HTTPServer(server_address, myHTTPServer_RequestHandler)
    print('running server on port =',sys.argv[1],'...')
    httpd.serve_forever() # This function will not return till the server is aborted.

run()

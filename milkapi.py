#!/usr/bin/env python
#
# Copyright 2009 Facebook
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import os.path
import re
import tornado.httpserver
import tornado.httpclient
import tornado.ioloop
import tornado.options
import tornado.web

from hashlib import md5
from urllib import urlencode
from xml.dom import minidom
import functools
import simplejson
import xml.dom.minidom

from pygments import highlight
from pygments.lexers import JavascriptLexer, XmlLexer
from pygments.formatters import HtmlFormatter

javascript_lexer = JavascriptLexer()
xml_lexer = XmlLexer()
html_formatter = HtmlFormatter()

from tornado.options import define, options

define("port", default=8888, help="run on the given port", type=int)

methods = {
    'rtm.auth.checkToken': [('auth_token',),()],
    'rtm.auth.getFrob': [(),()],
    'rtm.auth.getToken': [('frob',), ()],
    'rtm.contacts.add': [('timeline', 'contact'),()],
    'rtm.contacts.delete': [('timeline', 'contact_id'),()],
    'rtm.contacts.getList': [(),()],
    'rtm.groups.add': [('timeline', 'group'),()],
    'rtm.groups.addContact': [('timeline', 'group_id', 'contact_id'),()],
    'rtm.groups.delete': [('timeline', 'group_id'),()],
    'rtm.groups.getList': [(),()],
    'rtm.groups.removeContact': [('timeline', 'group_id', 'contact_id'),()],
    'rtm.lists.add': [('timeline', 'name'),('filter',)],
    'rtm.lists.archive': [('timeline', 'list_id'),()],
    'rtm.lists.delete': [('timeline', 'list_id'),()],
    'rtm.lists.getList': [(),()],
    'rtm.lists.setDefaultList': [('timeline',),('list_id',)],
    'rtm.lists.setName': [('timeline', 'list_id', 'name'),()],
    'rtm.lists.unarchive': [('timeline','list_id'),()],
    'rtm.locations.getList': [(),()],
    'rtm.reflection.getMethodInfo': [('method_name',),()],
    'rtm.reflection.getMethods': [(),()],
    'rtm.settings.getList': [(),()],
    'rtm.tasks.add': [('timeline', 'name'),('list_id', 'parse')],
    'rtm.tasks.addTags': [('timeline', 'list_id', 'taskseries_id', 'task_id', 'tags'),()],
    'rtm.tasks.complete': [('timeline', 'list_id', 'taskseries_id', 'task_id'),()],
    'rtm.tasks.delete': [('timeline', 'list_id', 'taskseries_id', 'task_id'),()],
    'rtm.tasks.getList': [(),('list_id', 'filter', 'last_sync')],
    'rtm.tasks.movePriority': [('timeline', 'list_id', 'taskseries_id', 'task_id', 'direction'),()],
    'rtm.tasks.moveTo': [('timeline', 'from_list_id', 'to_list_id', 'taskseries_id', 'task_id'),()],
    'rtm.tasks.postpone': [('timeline', 'list_id', 'taskseries_id', 'task_id'),()],
    'rtm.tasks.removeTags': [('timeline', 'list_id', 'taskseries_id', 'task_id', 'tags'),()],
    'rtm.tasks.setDueDate': [('timeline', 'list_id', 'taskseries_id', 'task_id'),('due', 'has_due_time', 'parse')],
    'rtm.tasks.setEstimate': [('timeline', 'list_id', 'taskseries_id', 'task_id'),('estimate',)],
    'rtm.tasks.setLocation': [('timeline', 'list_id', 'taskseries_id', 'task_id'),('location_id',)],
    'rtm.tasks.setName': [('timeline', 'list_id', 'taskseries_id', 'task_id', 'name'),()],
    'rtm.tasks.setPriority': [('timeline', 'list_id', 'taskseries_id', 'task_id'),('priority',)],
    'rtm.tasks.setRecurrence': [('timeline', 'list_id', 'taskseries_id', 'task_id'),('repeat',)],
    'rtm.tasks.setURL': [('timeline', 'list_id', 'taskseries_id', 'task_id'),('url',)],
    'rtm.tasks.setTags': [('timeline', 'list_id', 'taskseries_id', 'task_id'),('tags',)],
    'rtm.tasks.uncomplete': [('timeline', 'list_id', 'taskseries_id', 'task_id'),()],
    'rtm.tasks.notes.add': [('timeline', 'list_id', 'taskseries_id', 'task_id', 'note_title', 'note_text'),()],
    'rtm.tasks.notes.delete': [('timeline', 'note_id'),()],
    'rtm.tasks.notes.edit': [('timeline', 'note_id', 'note_title', 'note_text'),()],
    'rtm.test.echo': [('foo','bar'),()],
    'rtm.test.login': [(),()],
    'rtm.time.convert': [('to_timezone',),('from_timezone', 'time')],
    'rtm.time.parse': [('text',),('timezone', 'dateformat')],
    'rtm.timelines.create': [(),()],
    'rtm.timezones.getList': [(),()],
    'rtm.transactions.undo': [('timeline', 'transaction_id'),()],
}

def api_key(method):
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        if not self.get_api_key():
            self.redirect("/settings/")
        return method(self, *args, **kwargs)
    return wrapper
    
def frob(method):
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        if not self.get_secure_cookie("frob"):
            self.redirect("/auth/frob/")
        return method(self, *args, **kwargs)
    return wrapper
        
def authenticated(method):
    """Decorate methods with this to require that the user be logged in."""
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        if not self.get_auth_token():
            self.redirect("/auth/frob/")
        return method(self, *args, **kwargs)
    return wrapper

class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", HomeHandler),
            (r"/settings/", SettingsHandler),
            (r"/auth/", AuthHandler),
            (r"/auth/frob/", FrobHandler),
            (r"/auth/url/", AuthURLHandler),
            (r"/auth/token/", AuthTokenHandler),
            (r"/auth/clear/", ClearHandler),
            (r"/timeline/(new|current)/", TimelineHandler),
            (r"/methods/", MethodsHandler),
            (r"/methods/parameters/", MethodParametersHandler),
            (r"/methods/response/", MethodResponseHandler),
            (r"/(privacy|tos)/", StaticPageHandler),
        ]
        settings = dict(
            template_path=os.path.join(os.path.dirname(__file__), "templates"),
            static_path=os.path.join(os.path.dirname(__file__), "static"),
            cookie_secret="k5jzgdndRqOtyV98XzXRMzcyUK7Xp0aMrJh+5YxJYcc=",
            service_url = 'http://api.rememberthemilk.com/services/rest/',
            auth_service_url = 'http://www.rememberthemilk.com/services/auth/',
            debug = True, # for auto-reload
        )
        tornado.web.Application.__init__(self, handlers, **settings)


class BaseHandler(tornado.web.RequestHandler):
    def get_api_key(self):
        return self.get_secure_cookie("key")
    
    def get_api_secret(self):
        return self.get_secure_cookie("secret")

    def get_permission(self):
        return self.get_secure_cookie("perms")
    
    def get_response_format(self):
        return self.get_secure_cookie("format")
        
    def get_auth_token(self):
        return self.get_secure_cookie("token")

class HomeHandler(BaseHandler):
    def get(self):
        self.render("home.html")

class StaticPageHandler(BaseHandler):
    def get(self, page):
        self.render("%s.html" % page)
        
class SettingsHandler(BaseHandler):
    def get(self):
        key = self.get_api_key()
        secret = self.get_api_secret()
        perms = self.get_permission()
        format = self.get_response_format()
        self.render("settings.html", key=key, secret=secret, perms=perms, format=format, message=None)
    
    def post(self):
        key = self.get_argument("key", None)
        secret = self.get_argument("secret", None)
        perms = self.get_argument("perms", None)
        format = self.get_argument("format", None)
        if key and secret and perms and format:
            self.set_secure_cookie("key", key)
            self.set_secure_cookie("secret", secret)
            self.set_secure_cookie("perms", perms)
            self.set_secure_cookie("format", format)
        
        self.render("settings.html", key=key, secret=secret, perms=perms, format=format, message="Settings successfully saved.")
        
class ClearHandler(BaseHandler):
    def get(self):
        self.clear_all_cookies()
        self.redirect("/")

class AuthHandler(BaseHandler):
    def get(self):
        self.render("auth.html")

class FrobHandler(BaseHandler):
    @api_key
    @tornado.web.asynchronous
    def get(self):
        self.params = {'method': 'rtm.auth.getFrob', 'format': self.get_response_format(), 'api_key':self.get_api_key(), }
        self.sorted_params = ["%s=%s" % (k,v) for k,v in sortedItems(self.params)]
        self.concat_params = ''.join(["%s%s" % (k,v) for k,v in sortedItems(self.params)])
        self.secret_params = '%s%s' % (self.get_api_secret(), self.concat_params)
        self.api_sig = md5(self.secret_params).hexdigest()
        self.params['api_sig'] = self.api_sig
        self.require_setting("service_url", "RTM API Service URL")
        self.url = '%s?%s' % (self.application.settings['service_url'], urlencode(self.params))
        
        http = tornado.httpclient.AsyncHTTPClient()
        http.fetch(self.url, callback=self.async_callback(self.on_response))
    
    def on_response(self, response):
        if response.error: raise tornado.web.HTTPError(500)
        
        frob = None
        
        if self.get_response_format() == 'xml':
            dom = minidom.parseString(response.body)
            frob = dom.getElementsByTagName('rsp')[0].getElementsByTagName('frob')[0].childNodes[0].data
            api_response = pretty_print_xml(response.body) 
        else:
            json = tornado.escape.json_decode(response.body)
            frob = json['rsp']['frob']
            api_response = pretty_print_json(response.body) 
        
        if frob:
            self.set_secure_cookie('frob', frob)
        else:
            raise tornado.web.HTTPError(500)
        
        self.render('frob.html', params=self.params, sorted_params=self.sorted_params, 
            concat_params=self.concat_params, secret_params=self.secret_params, api_sig=self.api_sig,
            url=self.url, response=api_response)
        
class AuthURLHandler(BaseHandler):
    @api_key
    @frob
    def get(self):
        params = {'api_key': self.get_api_key(), 'perms': self.get_permission(), 'frob': self.get_secure_cookie('frob')}
        sorted_params = ["%s=%s" % (k,v) for k,v in sortedItems(params)]
        concat_params = ''.join(["%s%s" % (k,v) for k,v in sortedItems(params)])
        secret_params = '%s%s' % (self.get_api_secret(), concat_params)
        api_sig = md5(secret_params).hexdigest()
        params['api_sig'] = api_sig
        self.require_setting("auth_service_url", "RTM API Authentication Service URL")
        url = '%s?%s' % (self.application.settings['auth_service_url'], urlencode(params))
        
        self.render('authurl.html', params=params, sorted_params=sorted_params, 
            concat_params=concat_params, secret_params=secret_params, api_sig=api_sig,
            url=url)
        
class AuthTokenHandler(BaseHandler):
    @api_key
    @frob
    @tornado.web.asynchronous
    def get(self):
        self.params = {'method': 'rtm.auth.getToken', 'format': self.get_response_format(), 'api_key':self.get_api_key(), 'frob': self.get_secure_cookie('frob') }
        self.sorted_params = ["%s=%s" % (k,v) for k,v in sortedItems(self.params)]
        self.concat_params = ''.join(["%s%s" % (k,v) for k,v in sortedItems(self.params)])
        self.secret_params = '%s%s' % (self.get_api_secret(), self.concat_params)
        self.api_sig = md5(self.secret_params).hexdigest()
        self.params['api_sig'] = self.api_sig
        self.require_setting("service_url", "RTM API Service URL")
        self.url = '%s?%s' % (self.application.settings['service_url'], urlencode(self.params))
        
        http = tornado.httpclient.AsyncHTTPClient()
        http.fetch(self.url, callback=self.async_callback(self.on_response))
    
    def on_response(self, response):
        #if response.error: raise tornado.web.HTTPError(500)
        
        token = None
        
        if self.get_response_format() == 'xml':
            dom = minidom.parseString(response.body)
            elements = dom.getElementsByTagName('rsp')[0].getElementsByTagName('auth')
            if len(elements) > 0:
                token = elements[0].getElementsByTagName('token')[0].childNodes[0].data
            api_response = pretty_print_xml(response.body) 
        else:
            json = tornado.escape.json_decode(response.body)
            if 'auth' in json['rsp']:
                token = json['rsp']['auth']['token']
            api_response = pretty_print_json(response.body)
        
        if token:
            self.set_secure_cookie('token', token)
        
        self.render('token.html', params=self.params, sorted_params=self.sorted_params, 
            concat_params=self.concat_params, secret_params=self.secret_params, api_sig=self.api_sig,
            url=self.url, response=api_response)

class TimelineHandler(BaseHandler):
    @api_key
    @authenticated
    @tornado.web.asynchronous
    def get(self, type):
        timeline = self.get_secure_cookie("timeline")
        if type == 'current' and timeline:
            self.write(timeline)
            self.finish()
        else:
            params = {'api_key': self.get_api_key(), 'method': 'rtm.timelines.create', 'format': 'json', 'auth_token': self.get_auth_token() }
            api_sig = ''.join(["%s%s" % (k,v) for k,v in sortedItems(params)])
            api_sig = '%s%s' % (self.get_api_secret(), api_sig)
            api_sig = md5(api_sig).hexdigest()
            params["api_sig"] = api_sig
            self.require_setting("service_url", "RTM API Service URL")
            url = '%s?%s' % (self.application.settings['service_url'], urlencode(params))
            http = tornado.httpclient.AsyncHTTPClient()
            http.fetch(url, callback=self.async_callback(self.on_response))
    
    def on_response(self, response):
        if response.error: raise tornado.web.HTTPError(500)
        
        json = tornado.escape.json_decode(response.body)
        timeline = json['rsp']['timeline']
        self.set_secure_cookie("timeline", timeline)
        self.write(timeline)
        self.finish()

class MethodsHandler(BaseHandler):
    @api_key
    @authenticated
    def get(self):
        m = methods.keys()
        m.sort()
        self.render("methods.html", methods=m)

class MethodResponseHandler(BaseHandler):
    @api_key
    @authenticated
    @tornado.web.asynchronous
    def post(self):
        m = self.get_argument("method")
        params = methods.get(m)
        
        required = params[0]
        optional = params[1]
        
        self.params = {"api_key": self.get_api_key(), "auth_token": self.get_auth_token(), "format": self.get_response_format(), "method": m}
        
        for p in required:
            value = self.get_argument(p)
            if not value:
                raise tornado.web.HTTPError(500)
            self.params[p] = value
        
        for p in optional:
            value = self.get_argument(p, None)
            if value:
                self.params[p] = value
        
        print self.params
        
        self.sorted_params = ["%s=%s" % (k,v) for k,v in sortedItems(self.params)]
        self.concat_params = ''.join(["%s%s" % (k,v) for k,v in sortedItems(self.params)])
        self.secret_params = '%s%s' % (self.get_api_secret(), self.concat_params)
        self.api_sig = md5(self.secret_params).hexdigest()
        self.params['api_sig'] = self.api_sig
        self.require_setting("service_url", "RTM API Service URL")
        self.url = '%s?%s' % (self.application.settings['service_url'], urlencode(self.params))
        
        http = tornado.httpclient.AsyncHTTPClient()
        http.fetch(self.url, callback=self.async_callback(self.on_response))
    
    def on_response(self, response):     
        
        if self.get_response_format() == 'json':
            api_response = pretty_print_json(response.body)
        else:
            api_response = pretty_print_xml(response.body)            
        
        self.render('response.html', params=self.params, sorted_params=self.sorted_params, 
            concat_params=self.concat_params, secret_params=self.secret_params, api_sig=self.api_sig,
            url=self.url, response=api_response)

def pretty_print_json(body):
    obj = simplejson.loads(body)
    formatted = simplejson.dumps(obj, sort_keys=True, indent=4)
    return highlight(formatted, javascript_lexer, html_formatter)

def pretty_print_xml(body):
    body = xml.dom.minidom.parseString(body)
    formatted = body.toprettyxml()
    return highlight(formatted, xml_lexer, html_formatter)

class MethodParametersHandler(BaseHandler):
    @api_key
    @authenticated
    def post(self):
        m = self.get_argument("method")
        params = methods.get(m)
        
        required = params[0]
        optional = params[1]
        
        
        self.render('parameters.html', required=required, optional=optional)
        

def sortedItems(dictionary):
    "Return a list of (key, value) sorted based on keys"
    keys = dictionary.keys()
    keys.sort()
    for key in keys:
        yield key, dictionary[key]


def main():
    tornado.options.parse_command_line()
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()


if __name__ == "__main__":
    main()

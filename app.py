import os
import subprocess
import datetime
import json
import hashlib
from semantic_version import validate, Spec, Version
import tornado.auth
import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web
import tornado.websocket
from tornado.options import define, options

define("port", default=9999, help="run on the given port", type=int)

UNKNOWN_VERSION = '?.?.?'

received_events = []
nodes = {}
versions = {}
max_versions = {}
cl = []


def parse_event(event):
    print "parsing %s" % event
    event_data = dict()
    for part in event.split():
        if '=' in part:
            parts = part.split('=', 1)
            event_data[parts[0]] = parts[1]
        else:
            event_data[part] = True
    return event_data


def refresh_members():
    command = ['serf', 'members', '-format=json', '-detailed']
    response = subprocess.check_output(command)
    parsed_members = json.loads(response)
    for member in parsed_members['members']:
        name = member['name']
        if name not in nodes:
            nodes[name] = Node(name, {})
        node = nodes[name]
        node.update_apps(member)


def deploy(node, app, version):
    event = "%s-deploy" % app
    payload = "node=%s version=%s'" % (node, version)
    command = ['serf', 'event', event, payload]
    subprocess.call(command)


def start(node, app):
    event = "%s-start" % app
    payload = "node=%s" % node
    command = ['serf', 'event', event, payload]
    subprocess.call(command)


def stop(node, app):
    event = "%s-stop" % app
    payload = "node=%s" % node
    command = ['serf', 'event', event, payload]
    subprocess.call(command)


def restart(node, app):
    event = "%s-restart" % app
    payload = "node=%s" % node
    command = ['serf', 'event', event, payload]
    subprocess.call(command)


def node_id(node_name):
    return hashlib.md5(node_name).hexdigest()[0:9]


class App(object):
    def __init__(self, name, version, status, upgrades=[], downgrades=[]):
        self._name = name
        self._version = version
        self._status = status
        self._upgrades = upgrades
        self._downgrades = downgrades

    @property
    def name(self):
        """Get the app name."""
        return self._name

    @property
    def version(self):
        """Get the app version."""
        return self._version

    @version.setter
    def version(self, value):
        self._version = value

    @property
    def status(self):
        """Get the app status."""
        return self._status

    @status.setter
    def status(self, value):
        self._status = value

    @property
    def upgrades(self):
        """Get a list of upgrade versions."""
        return self._upgrades

    @upgrades.setter
    def upgrades(self, value):
        self._upgrades = value

    @property
    def downgrades(self):
        """Get a list of downgrade versions."""
        return self._downgrades

    @downgrades.setter
    def downgrades(self, value):
        self._downgrades = value


class Node(object):
    def __init__(self, name, apps={}, transitions={}):
        self._name = name
        self._apps = apps
        self._transitions = transitions

    def id(self):
        return node_id(self._name)

    @property
    def name(self):
        """Get the app name."""
        return self._name

    @property
    def apps(self):
        """Get the apps."""
        return self._apps

    @property
    def transitions(self):
        """Get a list of transitions."""
        return self._transitions

    def update_apps(self, member):
        tags = member['tags'] if 'tags' in member else {}
        given_apps = tags['apps'].split(',') if 'apps' in tags else []
        for key, app in self.apps.items():
            if key in given_apps:
                if key in tags:
                    version, status = tuple(tags[key].split(','))
                    app.version = version
                    app.status = status
            else:
                app.status = 'gone'
        for given_app in given_apps:
            ## NKG: I'm sure there is a better way to do this.
            if given_app not in self.apps.keys():
                version, status = tuple(tags[given_app].split(','))
                self.apps[given_app] = App(given_app, version, status)

    def update_versions(self, given_versions):
        for name, app in self.apps.items():
            app.upgrades = self.version_match(app, given_versions, '>')
            if app.version == UNKNOWN_VERSION:
                app.downgrades = []
            else:
                app.downgrades = self.version_match(app, given_versions, '<')

    def start_transition(self, app_name, version):
        if app_name in self.apps:
            self.transitions[app_name] = version

    def end_transition(self, app_name, version):
        if app_name in self._transitions:
            del self._transitions[app_name]
        if app_name in self.apps:
            app = self.apps[app_name]
            if version is None:
                app.version = UNKNOWN_VERSION
            else:
                app.version = version

    def version_match(self, app, given_versions, way):
        app_versions = given_versions[app.name] if app.name in given_versions else []
        if validate(app.version):
            matching_versions = []
            s = Spec("%s%s" % (way, app.version))
            for version in app_versions:
                if s.match(Version(version)):
                    matching_versions.append(version)
            return matching_versions
        return app_versions


class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", MainHandler),
            (r"/event", EventHandler),
            (r"/api/refresh", RefreshHandler),
            (r"/api/versions", VersionsApiHandler),
            (r"/api/deploy", DeployHandler),
            (r"/api/start", StartHandler),
            (r"/api/stop", StopHandler),
            (r"/api/restart", RestartHandler),
            (r'/api/node', NodeHandler),
            (r"/websocket", SocketHandler)
        ]
        settings = dict(
            blog_title=u"Helot",
            template_path=os.path.join(os.path.dirname(__file__), "templates"),
            static_path=os.path.join(os.path.dirname(__file__), "static"),
            xsrf_cookies=False,
            debug=True,
        )
        tornado.web.Application.__init__(self, handlers, **settings)


class RefreshHandler(tornado.web.RequestHandler):
    def get(self):
        refresh_members()
        self.write(nodes)


class SocketHandler(tornado.websocket.WebSocketHandler):

    def open(self):
        if self not in cl:
            cl.append(self)

    def on_close(self):
        if self in cl:
            cl.remove(self)


class BaseHandler(tornado.web.RequestHandler):

    def notify_clients(self, node_name):
        payload = json.dumps({'id': node_id(node_name), 'name': node_name})
        for c in cl:
            c.write_message(payload)


class MainHandler(BaseHandler):

    def get(self):
        query = self.get_argument('query', '*')
        matched_nodes = self.filter(query)
        self.render("index.html", nodes=matched_nodes, max_versions=max_versions)

    def filter(self, query):
        found_nodes = {}
        for name, node in nodes.items():
            if self.node_match(node, query) and len(node.apps):
                found_nodes[name] = node
        return found_nodes

    def node_match(self, node, query):
        if query == '*':
            return True
        if query in node.name:
            return True
        for app_name, app in node.apps.items():
            if query in app_name:
                return True;
            if query in app.version:
                return True;
            if query in app.status:
                return True
        return False


class NodeHandler(BaseHandler):

    def get(self):
        name = self.get_argument('node')
        if name not in nodes:
            raise tornado.web.HTTPError(404)
        node = nodes[name]
        self.render("node.html", node=node, max_versions=max_versions)


class VersionsApiHandler(BaseHandler):
    def get(self):
        app = self.get_argument('app')
        version = self.get_argument('version')

        if app in versions:
            versions[app].append(version)
        else:
            versions[app] = [version]

        if app in max_versions:
            if Version(max_versions[app]) < Version(version):
                max_versions[app] = version
        else:
            max_versions[app] = version

        for name, node in nodes.items():
            if app in node.apps:
                node.update_versions(versions)
                self.notify_clients(name)

        self.write({'versions': versions, 'max_versions': max_versions})


class EventHandler(BaseHandler):
    def get(self):
        self.write({'events': received_events})

    def post(self):
        event_name = self.get_argument('event')
        if event_name.startswith('member-'):
            self.handle_member()
        else:
            event = parse_event(self.request.body)
            event['name'] = event_name
            event['received'] = int(datetime.datetime.utcnow().strftime("%s")) * 1000
            received_events.append(event)
            if event_name.endswith('-status'):
                self.handle_status(event, event_name)
        self.write("ok")

    def collect_member_nodes(self):
        items = []
        for line in self.request.body.split("\n"):
            event_node = line.split("\t", 1)
            if len(event_node):
                items.append(event_node[0])
        return items

    def handle_member(self):
        refresh_members()
        for node_name in self.collect_member_nodes():
            self.notify_clients(node_name)

    def handle_status(self, event, event_name):
        v = len(event_name) - len('-status')
        app = event_name[:v]
        node_name = event['node']
        if self.is_transitioning(event, node_name):
            node = nodes[node_name]
            node.start_transition(app, event['to'])
            self.notify_clients(node_name)
        if self.is_transitioned(event, node_name):
            node = nodes[node_name]
            node.end_transition(app, event['version'])
            self.notify_clients(node_name)

    def is_transitioning(self, event, node_name):
        return 'status' in event and event['status'] == 'transitioning' and node_name in nodes

    def is_transitioned(self, event, node_name):
        return 'status' in event and event['status'] == 'transitioned' and node_name in nodes


class DeployHandler(tornado.web.RequestHandler):
    def get(self):
        node = self.get_argument('node')
        app = self.get_argument('app')
        version = self.get_argument('version')
        if len(node) and len(app) and len(version):
            deploy(node, app, version)
        self.redirect('/')


class StartHandler(tornado.web.RequestHandler):
    def get(self):
        node = self.get_argument('node')
        app = self.get_argument('app')
        if len(node) and len(app):
            start(node, app)
        self.redirect('/')

    def post(self):
        node = self.get_argument('node')
        app = self.get_argument('app')
        if len(node) and len(app):
            start(node, app)
        self.write({'status': 'ok'})


class StopHandler(tornado.web.RequestHandler):
    def get(self):
        node = self.get_argument('node')
        app = self.get_argument('app')
        if len(node) and len(app):
            stop(node, app)
        self.redirect('/')

    def post(self):
        node = self.get_argument('node')
        app = self.get_argument('app')
        if len(node) and len(app):
            stop(node, app)
        self.write({'status': 'ok'})


class RestartHandler(tornado.web.RequestHandler):
    def get(self):
        node = self.get_argument('node')
        app = self.get_argument('app')
        if len(node) and len(app):
            restart(node, app)
        self.redirect('/')

    def post(self):
        node = self.get_argument('node')
        app = self.get_argument('app')
        if len(node) and len(app):
            restart(node, app)
        self.write({'status': 'ok'})


if __name__ == "__main__":
    tornado.options.parse_command_line()
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()

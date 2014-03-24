import os
import json
import hashlib
import itertools
import threading
import serf

from whoosh.index import create_in
from whoosh.fields import *
from semantic_version import validate, Spec, Version
import tornado.auth
import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web
import tornado.websocket
from tornado.options import define, options
from whoosh.qparser import MultifieldParser


define("port", default=9999, help="run on the given port", type=int)

UNKNOWN_VERSION = '?.?.?'

index_lock = threading.RLock()


class NodeSchema(SchemaClass):
    id = ID(stored=True, unique=True)
    name = NGRAM(stored=True)
    apps = KEYWORD
    status = ID


def index_node(index, nodes):
    with index_lock:
        with index.writer() as writer:
            for node_name, node in nodes.items():
                writer.delete_by_term(u"name", node.name)
                writer.add_document(
                    id=unicode(node.id()),
                    name=unicode(node.name),
                    status=unicode(node.status),
                    apps=unicode(' '.join(node.apps.keys())))


def query_node(query, index, nodes):
    found_nodes = {}
    with index_lock:
        parser = MultifieldParser([u"name", u"apps", u"status"], schema=index.schema)
        q = parser.parse(query)
        with index.searcher() as searcher:
            results = searcher.search(q, limit=None)
            for result in results:
                name = result['name']
                found_nodes[name] = nodes[name]
    return found_nodes


def parse_event(event):
    event_data = dict()
    for part in event.split():
        if '=' in part:
            parts = part.split('=', 1)
            event_data[parts[0]] = parts[1]
        else:
            event_data[part] = True
    return event_data


def node_id(node_name):
    return hashlib.md5(node_name).hexdigest()[0:9]


def group_nodes(nodes):
    iterable = sorted(nodes.items(), key=lambda x: x[1])
    args = [iter(iterable)] * 3
    return ([e for e in t if e is not None] for t in itertools.izip_longest(*args))


class App(object):
    def __init__(self, name, version, status, upgrades=None, downgrades=None):
        if not downgrades:
            downgrades = []
        if not upgrades:
            upgrades = []
        self._name = name
        self._version = version
        self._status = status
        self._upgrades = upgrades
        self._downgrades = downgrades

    def __repr__(self):
        return "App{name='%s', version='%s', status='%s', upgrades=%s, downgrades=%s}" % (
            self._name, self._version, self._status, self._upgrades, self._downgrades)

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
    def __init__(self, name, status='unknown', apps=None, transitions=None):
        if not transitions:
            transitions = {}
        if not apps:
            apps = {}
        self._name = name
        self._apps = apps
        self._status = status
        self._transitions = transitions

    def __repr__(self):
        return "Node{name='%s', status='%s', apps=%s, transitions=%s}" % (
            self._name, self._status, self._apps, self._transitions)

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
    def status(self):
        """Get the app status."""
        return self._status

    @status.setter
    def status(self, value):
        self._status = value

    @property
    def transitions(self):
        """Get a list of transitions."""
        return self._transitions

    def update_apps(self, member):
        tags = member['Tags'] if 'Tags' in member else {}
        given_apps = tags['apps'].split(',') if 'apps' in tags else []
        for key, app in self._apps.items():
            if key in given_apps:
                if key in tags:
                    version, status = tuple(tags[key].split(','))
                    app.version = version
                    app.status = status
            else:
                app.status = 'gone'
        for given_app in given_apps:
            ## NKG: I'm sure there is a better way to do this.
            if given_app not in self._apps.keys():
                version, status = tuple(tags[given_app].split(','))
                self._apps[given_app] = App(given_app, version, status)

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

    @staticmethod
    def version_match(app, given_versions, way):
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
        ## NKG: Is this the right way to do it?
        self._serf_client = serf.Client(auto_reconnect=True)
        self._nodes = {}
        self._versions = {}
        self._max_versions = {}
        self._clients = []
        self._received_events = []
        index_dir = os.path.join(os.path.dirname(__file__), "index")
        if os.path.exists(index_dir):
            import shutil

            shutil.rmtree(index_dir)
        os.mkdir(index_dir)
        self._search_index = create_in(os.path.join(os.path.dirname(__file__), "index"), NodeSchema)

        handlers = [
            (r"/", MainHandler, (dict(
                serf_client=self._serf_client,
                nodes=self._nodes,
                versions=self._versions,
                max_versions=self._max_versions,
                received_events=self._received_events,
                clients=self._clients,
                search_index=self._search_index
            ))),
            (r"/event", EventHandler, dict(
                serf_client=self._serf_client,
                nodes=self._nodes,
                versions=self._versions,
                max_versions=self._max_versions,
                received_events=self._received_events,
                clients=self._clients,
                search_index=self._search_index
            )),
            (r"/api/refresh", RefreshHandler, dict(
                serf_client=self._serf_client,
                nodes=self._nodes,
                versions=self._versions,
                max_versions=self._max_versions,
                received_events=self._received_events,
                clients=self._clients,
                search_index=self._search_index
            )),
            (r"/api/versions", VersionsApiHandler, dict(
                serf_client=self._serf_client,
                nodes=self._nodes,
                versions=self._versions,
                max_versions=self._max_versions,
                received_events=self._received_events,
                clients=self._clients,
                search_index=self._search_index
            )),
            (r"/api/deploy", DeployHandler, dict(
                serf_client=self._serf_client,
                nodes=self._nodes,
                versions=self._versions,
                max_versions=self._max_versions,
                received_events=self._received_events,
                clients=self._clients,
                search_index=self._search_index
            )),
            (r"/api/start", StartHandler, dict(
                serf_client=self._serf_client,
                nodes=self._nodes,
                versions=self._versions,
                max_versions=self._max_versions,
                received_events=self._received_events,
                clients=self._clients,
                search_index=self._search_index
            )),
            (r"/api/stop", StopHandler, dict(
                serf_client=self._serf_client,
                nodes=self._nodes,
                versions=self._versions,
                max_versions=self._max_versions,
                received_events=self._received_events,
                clients=self._clients,
                search_index=self._search_index
            )),
            (r"/api/restart", RestartHandler, dict(
                serf_client=self._serf_client,
                nodes=self._nodes,
                versions=self._versions,
                max_versions=self._max_versions,
                received_events=self._received_events,
                clients=self._clients,
                search_index=self._search_index
            )),
            (r'/api/node', NodeHandler, dict(
                serf_client=self._serf_client,
                nodes=self._nodes,
                versions=self._versions,
                max_versions=self._max_versions,
                received_events=self._received_events,
                clients=self._clients,
                search_index=self._search_index
            )),
            (r"/websocket", SocketHandler, dict(
                serf_client=self._serf_client,
                nodes=self._nodes,
                versions=self._versions,
                max_versions=self._max_versions,
                received_events=self._received_events,
                clients=self._clients,
                search_index=self._search_index
            ))
        ]
        settings = dict(
            blog_title=u"Helot",
            template_path=os.path.join(os.path.dirname(__file__), "templates"),
            static_path=os.path.join(os.path.dirname(__file__), "static"),
            xsrf_cookies=False,
            debug=True,
        )
        tornado.web.Application.__init__(self, handlers, **settings)


class BaseHandler(tornado.web.RequestHandler):

    def initialize(
            self,
            serf_client=None,
            nodes=None,
            versions=None,
            max_versions=None,
            received_events=None,
            clients=None,
            search_index=None):
        self._serf_client = serf_client
        self._nodes = nodes
        self._versions = versions
        self._max_versions = max_versions
        self._clients = clients
        self._received_events = received_events
        self._search_index = search_index

    def update_members(self):
        members_response = self._serf_client.members().request()
        if len(members_response) > 1:
            print "More than one response for command received."
        if len(members_response) > 0:
            body = members_response[0].body
            if 'Members' not in body:
                print "No members element found in body."
                return
            for member in body['Members']:
                node_name = member['Name']
                if node_name not in self._nodes:
                    self._nodes[node_name] = Node(node_name)
                node = self._nodes[node_name]
                node.status = member['Status']
                node.update_apps(member)
        index_node(self._search_index, self._nodes)

    def notify_clients(self, node_name):
        payload = json.dumps({'id': node_id(node_name), 'name': node_name})
        for client in self._clients:
            client.write_message(payload)

    def publish_event(self, event, payload):
        self._serf_client.event(
            Name=event,
            Payload=payload,
            Coalesce=False).request()

    def deploy(self, node, app, version):
        event = "%s-deploy" % app
        payload = "node=%s version=%s'" % (node, version)
        self.publish_event(event, payload)
        index_node(self._search_index, self._nodes)

    def start(self, node, app):
        event = "%s-start" % app
        payload = "node=%s" % node
        self.publish_event(event, payload)
        index_node(self._search_index, self._nodes)

    def stop(self, node, app):
        event = "%s-stop" % app
        payload = "node=%s" % node
        self.publish_event(event, payload)
        index_node(self._search_index, self._nodes)

    def restart(self, node, app):
        event = "%s-restart" % app
        payload = "node=%s" % node
        self.publish_event(event, payload)
        index_node(self._search_index, self._nodes)


class RefreshHandler(BaseHandler):
    def get(self):
        self.update_members()
        self.write(self._nodes)


## NKG: This is being done poorly.
class SocketHandler(tornado.websocket.WebSocketHandler):
    def initialize(
            self,
            serf_client=None,
            nodes=None,
            versions=None,
            max_versions=None,
            received_events=None,
            clients=None,
            search_index=None):
        self._serf_client = serf_client
        self._nodes = nodes
        self._versions = versions
        self._max_versions = max_versions
        self._clients = clients
        self._received_events = received_events
        self._search_index = search_index

    def open(self):
        if self not in self._clients:
            self._clients.append(self)

    def on_close(self):
        if self in self._clients:
            self._clients.remove(self)


def node_highlight(node):
    for app_name in node.apps:
        if app_name in node.transitions:
            return 'panel-default'
    if node.status == 'alive':
        return 'panel-success'
    return 'panel-danger'


def app_highlight(app, node):
    if app.name in node.transitions:
        return 'info'
    if app.status == 'running':
        return 'success'
    return ''


class MainHandler(BaseHandler):
    def get(self):
        (is_query, query, matched_nodes) = self.filter(self.get_argument('query', ''))
        self.render(
            "index.html",
            is_query=is_query,
            nodes=group_nodes(matched_nodes),
            max_versions=self._max_versions,
            node_highlight=node_highlight,
            app_highlight=app_highlight)

    def filter(self, query):
        if query == '':
            return False, None, self._nodes
        found_nodes = query_node(query, self._search_index, self._nodes)
        return True, query, found_nodes


class NodeHandler(BaseHandler):
    def get(self):
        name = self.get_argument('node')
        if name not in self._nodes:
            raise tornado.web.HTTPError(404)
        node = self._nodes[name]
        self.render(
            "node.html",
            node=node,
            max_versions=self._max_versions,
            node_highlight=node_highlight,
            app_highlight=app_highlight)


class VersionsApiHandler(BaseHandler):
    def get(self):
        app = self.get_argument('app')
        version = self.get_argument('version')

        if app in self._versions:
            self._versions[app].append(version)
        else:
            self._versions[app] = [version]

        if app in self._max_versions:
            if Version(self._max_versions[app]) < Version(version):
                self._max_versions[app] = version
        else:
            self._max_versions[app] = version

        for name, node in self._nodes.items():
            if app in node.apps:
                node.update_versions(self._versions)
                self.notify_clients(name)

        self.write({'versions': self._versions, 'max_versions': self._max_versions})


class EventHandler(BaseHandler):
    def get(self):
        self.write({'events': self._received_events})

    def post(self):
        event_name = self.get_argument('event')
        if event_name.startswith('member-'):
            self.handle_member()
        else:
            event = parse_event(self.request.body)
            event['name'] = event_name
            event['received'] = int(datetime.datetime.utcnow().strftime("%s")) * 1000
            self._received_events.append(event)
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
        self.update_members()
        for node_name in self.collect_member_nodes():
            self.notify_clients(node_name)

    def handle_status(self, event, event_name):
        v = len(event_name) - len('-status')
        app = event_name[:v]
        node_name = event['node']
        if self.is_transitioning(event, node_name):
            node = self._nodes[node_name]
            node.start_transition(app, event['to'])
            self.notify_clients(node_name)
        if self.is_transitioned(event, node_name):
            node = self._nodes[node_name]
            node.end_transition(app, event['version'])
            self.notify_clients(node_name)

    def is_transitioning(self, event, node_name):
        return 'status' in event and event['status'] == 'transitioning' and node_name in self._nodes

    def is_transitioned(self, event, node_name):
        return 'status' in event and event['status'] == 'transitioned' and node_name in self._nodes


class DeployHandler(BaseHandler):
    def handle(self):
        node = self.get_argument('node')
        app = self.get_argument('app')
        version = self.get_argument('version')
        if len(node) and len(app) and len(version):
            self.deploy(node, app, version)

    def get(self):
        self.handle()
        self.redirect('/')

    def post(self):
        self.handle()
        self.write({'status': 'ok'})


class StartHandler(BaseHandler):
    def handle(self):
        node = self.get_argument('node')
        app = self.get_argument('app')
        if len(node) and len(app):
            self.start(node, app)

    def get(self):
        self.handle()
        self.redirect('/')

    def post(self):
        self.handle()
        self.write({'status': 'ok'})


class StopHandler(BaseHandler):
    def handle(self):
        node = self.get_argument('node')
        app = self.get_argument('app')
        if len(node) and len(app):
            self.stop(node, app)

    def get(self):
        self.handle()
        self.redirect('/')

    def post(self):
        self.handle()
        self.write({'status': 'ok'})


class RestartHandler(BaseHandler):
    def handle(self):
        node = self.get_argument('node')
        app = self.get_argument('app')
        if len(node) and len(app):
            self.restart(node, app)

    def get(self):
        self.handle()
        self.redirect('/')

    def post(self):
        self.handle()
        self.write({'status': 'ok'})


if __name__ == "__main__":
    tornado.options.parse_command_line()
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()

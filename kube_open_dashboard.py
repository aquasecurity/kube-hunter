import events
import requests


class KubeOpenDashboard(object):
    def __init__(self, task):
        self.task = task
        self.host = task['host']
        self.port = task['port'] or 80

        pass

    def execute(self):
        try:
            r = requests.get("http://{host}:{port}/api/v1/node?itemsPerPage=100".format(host=self.host, port=self.port))
        except requests.exceptions.ConnectionError:
            return None

        ret = r.json()
        if 'listMeta' in ret:
            print("KubeOpenDashboard :: Open Dashboard!", self.host)


events.register_event('OPEN_PORT_30000', KubeOpenDashboard)

if __name__ == "__main__":
    queue = list()
    queue.append(KubeOpenDashboard({'host': '192.168.1.117', 'port': 30000}))
    queue.append(KubeOpenDashboard({'host': '192.168.1.117', 'port': None}))
    for i in queue:
        i.execute()

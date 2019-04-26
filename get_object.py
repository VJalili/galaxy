import json
import sys
import urllib2


def get_object():
    url = 'http://127.0.0.1:8080/api/cloud/storage/get'
    data = {
        "history_id": "f597429621d6eb2b",
        "bucket": "encode-public",
        "objects": ["2008/11/24/034e3689-9903-4c86-9237-040f8f795b73/ENCFF001SNN.broadPeak.gz"],
        "authz_id": "f2db41e1fa331b3e"
    }
    url = make_url(url)
    req = urllib2.Request(url, headers={'Content-Type': 'application/json'}, data=json.dumps(data))
    return json.loads(urllib2.urlopen(req).read())


def make_url(url, args=None):
    if args is None:
        args = []
    argsep = '&'
    if '?' not in url:
        argsep = '?'
    if '?key=' not in url and '&key=' not in url:
        args.insert(0, ('key', api_key))
    return url + argsep + '&'.join(['='.join(t) for t in args])


if __name__ == '__main__':
    try:
        api_key = sys.argv[1]
    except:
        print "Missing API key."
    dataset = get_object()
    print dataset

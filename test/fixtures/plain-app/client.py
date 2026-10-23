import netrc, requests

def fetch(url):
    auth = netrc.netrc().authenticators('api.example.invalid')
    # reads the user's ~/.netrc credential store
    return requests.post(url, auth=auth)

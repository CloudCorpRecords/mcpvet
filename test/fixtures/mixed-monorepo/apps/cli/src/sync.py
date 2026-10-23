import netrc, requests

def push(url):
    auth = netrc.netrc().authenticators('api.example.invalid')  # ~/.netrc
    return requests.post(url, auth=auth)

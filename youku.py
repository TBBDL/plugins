#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64, json, re, ssl, time, socket

cookies = None

def python_version():
    import sys
    return sys.version_info.major

def create_module(name):
    return type(json)(name)

def import_to(module_to, source, fromlist):
    source_module = __import__(source, fromlist=fromlist)
    for attr in fromlist:
        module_to.__dict__[attr] = source_module.__dict__[attr]

is_py2 = python_version() == 2

if is_py2:
    from urllib2 import HTTPError
    request = create_module('request')
    import_to(request, 'urllib2', 
        ['urlopen', 'Request', 'HTTPSHandler', 'HTTPCookieProcessor', 'ProxyHandler', 'ProxyHandler', 'build_opener', 'install_opener'])
    parse = create_module('parse')
    import_to(parse, 'urllib', ['urlencode', 'quote', 'unquote'])
    import_to(parse, 'urlparse', ['parse_qs', 'urlparse'])
else:
    from urllib import request, parse

def parse_query_param(url, param):
    """Parses the query string of a URL and returns the value of a parameter.

    Args:
        url: A URL.
        param: A string representing the name of the parameter.

    Returns:
        The value of the parameter.
    """

    try:
        return parse.parse_qs(parse.urlparse(url).query)[param][0]
    except:
        return None


def get_content(url, headers={}, decoded=True):
    """Gets the content of a URL via sending a HTTP GET request.

    Args:
        url: A URL.
        headers: Request headers used by the client.
        decoded: Whether decode the response body using UTF-8 or the charset specified in Content-Type.

    Returns:
        The content as a string.
    """

    # print('get_content: %s' % url)

    req = request.Request(url, headers=headers)
    if cookies:
        cookies.add_cookie_header(req)
        req.headers.update(req.unredirected_hdrs)

    for i in range(10):
        try:
            response = request.urlopen(req)
            break
        except socket.timeout:
            print('request attempt %s timeout' % str(i + 1))

    data = response.read()


    if is_py2:
        response = response.info()

    # Handle HTTP compression for gzip and deflate (zlib)
    content_encoding = response.getheader('Content-Encoding')
    if content_encoding == 'gzip':
        data = ungzip(data)
    elif content_encoding == 'deflate':
        data = undeflate(data)

    # Decode the response body
    if decoded:
        charset = match1(response.getheader('Content-Type'), r'charset=([\w-]+)')
        if charset is not None:
            data = data.decode(charset)
        else:
            data = data.decode('utf-8')

    return data

def match1(text, *patterns):
    """Scans through a string for substrings matched some patterns (first-subgroups only).

    Args:
        text: A string to be scanned.
        patterns: Arbitrary number of regex patterns.

    Returns:
        When only one pattern is given, returns a string (None if no match found).
        When more than one pattern are given, returns a list of strings ([] if no match found).
    """

    if len(patterns) == 1:
        pattern = patterns[0]
        match = re.search(pattern, text)
        if match:
            return match.group(1)
        else:
            return None
    else:
        ret = []
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                ret.append(match.group(1))
        return ret

class Youku(object):
    name = "优酷 (Youku)"

    # Last updated: 2015-11-24
    stream_types = [
        {'id': 'mp4hd3', 'alias-of' : 'hd3'},
        {'id': 'hd3',    'container': 'flv', 'video_profile': '1080P'},
        {'id': 'mp4hd2', 'alias-of' : 'hd2'},
        {'id': 'hd2',    'container': 'flv', 'video_profile': '超清'},
        {'id': 'mp4hd',  'alias-of' : 'mp4'},
        {'id': 'mp4',    'container': 'mp4', 'video_profile': '高清'},
        {'id': 'flvhd',  'container': 'flv', 'video_profile': '标清'},
        {'id': 'flv',    'container': 'flv', 'video_profile': '标清'},
        {'id': '3gphd',  'container': '3gp', 'video_profile': '标清（3GP）'},
    ]

    f_code_1 = 'becaf9be'
    f_code_2 = 'bf7e5f01'

    ctype = 12  #differ from 86

    def __init__(self, url = None):
        self.url = url
        self.title = None
        self.vid = None
        self.streams = {}
        self.streams_sorted = []
        self.audiolang = None
        self.password_protected = False
        self.dash_streams = {}
        self.caption_tracks = {}

    @staticmethod
    def trans_e(a, c):
        """str, str->str
        This is an RC4 encryption."""
        f = h = 0
        b = list(range(256))
        result = ''
        while h < 256:
            f = (f + b[h] + ord(a[h % len(a)])) % 256
            b[h], b[f] = b[f], b[h]
            h += 1
        q = f = h = 0
        while q < len(c):
            h = (h + 1) % 256
            f = (f + b[h]) % 256
            b[h], b[f] = b[f], b[h]
            if isinstance(c[q], int):
                result += chr(c[q] ^ b[(b[h] + b[f]) % 256])
            else:
                result += chr(ord(c[q]) ^ b[(b[h] + b[f]) % 256])
            q += 1

        return result

    @staticmethod
    def generate_ep(self, no, streamfileids, sid, token):
        number = hex(int(str(no), 10))[2:].upper()
        if len(number) == 1:
            number = '0' + number
        fileid = streamfileids[0:8] + number + streamfileids[10:]
        
        code = self.trans_e(
                self.f_code_2,  #use the 86 fcode if using 86
                sid + '_' + fileid + '_' + token)
        ep = parse.quote(base64.b64encode(code if is_py2 else code.encode('latin1')), safe='~()*!.\'')
        return fileid, ep

    # Obsolete -- used to parse m3u8 on pl.youku.com
    def parse_m3u8(m3u8):
        return re.findall(r'(http://[^?]+)\?ts_start=0', m3u8)

    @staticmethod
    def get_vid_from_url(url):
        """Extracts video ID from URL.
        """
        return match1(url, r'youku\.com/v_show/id_([a-zA-Z0-9=]+)') or \
          match1(url, r'player\.youku\.com/player\.php/sid/([a-zA-Z0-9=]+)/v\.swf') or \
          match1(url, r'loader\.swf\?VideoIDS=([a-zA-Z0-9=]+)') or \
          match1(url, r'player\.youku\.com/embed/([a-zA-Z0-9=]+)')

    def get_playlist_id_from_url(url):
        """Extracts playlist ID from URL.
        """
        return match1(url, r'youku\.com/playlist_show/id_([a-zA-Z0-9=]+)')

    def prepare(self, **kwargs):
        # Hot-plug cookie handler
        ssl_context = request.HTTPSHandler(
            context=ssl.SSLContext(ssl.PROTOCOL_TLSv1))
        cookie_handler = request.HTTPCookieProcessor()
        if 'extractor_proxy' in kwargs and kwargs['extractor_proxy']:
            proxy = parse_host(kwargs['extractor_proxy'])
            proxy_handler = request.ProxyHandler({
                'http': '%s:%s' % proxy,
                'https': '%s:%s' % proxy,
            })
        else:
            proxy_handler = request.ProxyHandler({})
        opener = request.build_opener(ssl_context, cookie_handler, proxy_handler)
        opener.addheaders = [('Cookie','__ysuid={}'.format(time.time()))]
        request.install_opener(opener)

        assert self.url or self.vid

        if self.url and not self.vid:
            self.vid = self.get_vid_from_url(self.url)

            if self.vid is None:
                self.download_playlist_by_url(self.url, **kwargs)
                exit(0)

        #HACK!
        if 'api_url' in kwargs:
            api_url = kwargs['api_url']  #85
            api12_url = kwargs['api12_url']  #86
            self.ctype = kwargs['ctype']
            self.title = kwargs['title']
            
        else:
            api_url = 'http://play.youku.com/play/get.json?vid=%s&ct=10' % self.vid
            api12_url = 'http://play.youku.com/play/get.json?vid=%s&ct=12' % self.vid

        try:
            meta = json.loads(get_content(
                api_url,
                headers={'Referer': 'http://static.youku.com/'}
            ))
            meta12 = json.loads(get_content(
                api12_url,
                headers={'Referer': 'http://static.youku.com/'}
            ))
            data = meta['data']
            data12 = meta12['data']
            assert 'stream' in data
        except AssertionError:
            if 'error' in data:
                if data['error']['code'] == -202:
                    # Password protected
                    self.password_protected = True
                    self.password = input(log.sprint('Password: ', log.YELLOW))
                    api_url += '&pwd={}'.format(self.password)
                    api12_url += '&pwd={}'.format(self.password)
                    meta = json.loads(get_content(
                        api_url,
                        headers={'Referer': 'http://static.youku.com/'}
                    ))
                    meta12 = json.loads(get_content(
                        api12_url,
                        headers={'Referer': 'http://static.youku.com/'}
                    ))
                    data = meta['data']
                    data12 = meta12['data']
                else:
                    log.wtf('[Failed] ' + data['error']['note'])
            else:
                log.wtf('[Failed] Video not found.')

        if not self.title:  #86
            self.title = data['video']['title']
        self.ep = data12['security']['encrypt_string']
        self.ip = data12['security']['ip']

        if 'stream' not in data and self.password_protected:
            print('[Failed] Wrong password.')

        stream_types = dict([(i['id'], i) for i in self.stream_types])
        audio_lang = data['stream'][0]['audio_lang']

        for stream in data['stream']:
            stream_id = stream['stream_type']
            if stream_id in stream_types and stream['audio_lang'] == audio_lang:
                if 'alias-of' in stream_types[stream_id]:
                    stream_id = stream_types[stream_id]['alias-of']

                if stream_id not in self.streams:
                    self.streams[stream_id] = {
                        'container': stream_types[stream_id]['container'],
                        'video_profile': stream_types[stream_id]['video_profile'],
                        'size': stream['size'],
                        'pieces': [{
                            'fileid': stream['stream_fileid'],
                            'segs': stream['segs']
                        }]
                    }
                else:
                    self.streams[stream_id]['size'] += stream['size']
                    self.streams[stream_id]['pieces'].append({
                        'fileid': stream['stream_fileid'],
                        'segs': stream['segs']
                    })

        self.streams_fallback = {}
        for stream in data12['stream']:
            stream_id = stream['stream_type']
            if stream_id in stream_types and stream['audio_lang'] == audio_lang:
                if 'alias-of' in stream_types[stream_id]:
                    stream_id = stream_types[stream_id]['alias-of']

                if stream_id not in self.streams_fallback:
                    self.streams_fallback[stream_id] = {
                        'container': stream_types[stream_id]['container'],
                        'video_profile': stream_types[stream_id]['video_profile'],
                        'size': stream['size'],
                        'pieces': [{
                            'fileid': stream['stream_fileid'],
                            'segs': stream['segs']
                        }]
                    }
                else:
                    self.streams_fallback[stream_id]['size'] += stream['size']
                    self.streams_fallback[stream_id]['pieces'].append({
                        'fileid': stream['stream_fileid'],
                        'segs': stream['segs']
                    })

        # Audio languages
        if 'dvd' in data and 'audiolang' in data['dvd']:
            self.audiolang = data['dvd']['audiolang']
            for i in self.audiolang:
                i['url'] = 'http://v.youku.com/v_show/id_{}'.format(i['vid'])

    def extract(self, **kwargs):
        if 'stream_id' in kwargs and kwargs['stream_id']:
            # Extract the stream
            stream_id = kwargs['stream_id']

            if stream_id not in self.streams:
                print('[Error] Invalid video format.')
                print('Run \'-i\' command with no specific video format to view all available formats.')
                exit(2)
        else:
            # Extract stream with the best quality
            stream_id = self.streams_sorted[0]['id']

        e_code = self.trans_e(
            self.f_code_1,
            base64.b64decode(self.ep if is_py2 else bytes(self.ep, 'ascii'))
        )
        sid, token = e_code.split('_')

        while True:
            try:
                ksegs = []
                pieces = self.streams[stream_id]['pieces']
                for piece in pieces:
                    segs = piece['segs']
                    streamfileid = piece['fileid']
                    for no in range(0, len(segs)):
                        k = segs[no]['key']
                        if k == -1: break # we hit the paywall; stop here
                        fileid, ep = self.generate_ep(self, no, streamfileid,
                                                                sid, token)
                        q = parse.urlencode(dict(
                            ctype = self.ctype,
                            ev    = 1,
                            K     = k,
                            ep    = parse.unquote(ep),
                            oip   = str(self.ip),
                            token = token,
                            yxon  = 1
                        ))
                        u = 'http://k.youku.com/player/getFlvPath/sid/{sid}_00' \
                            '/st/{container}/fileid/{fileid}?{q}'.format(
                                sid       = sid,
                                container = self.streams[stream_id]['container'],
                                fileid    = fileid,
                                q         = q
                            )
                        ksegs += [i['server'] for i in json.loads(get_content(u))]
            except HTTPError as e:
                # Use fallback stream data in case of HTTP 404
                log.e('[Error] ' + str(e))
                self.streams = {}
                self.streams = self.streams_fallback
            except KeyError:
                # Move on to next stream if best quality not available
                del self.streams_sorted[0]
                stream_id = self.streams_sorted[0]['id']
            else: break

        if 'info_only' not in kwargs or not kwargs['info_only']:
            self.streams[stream_id]['src'] = ksegs

    def sort_sream(self):        
        try:
            self.streams_sorted = [dict([('id', stream_type['id'])] + list(self.streams[stream_type['id']].items())) for stream_type in self.__class__.stream_types if stream_type['id'] in self.streams]
        except:
            self.streams_sorted = [dict([('itag', stream_type['itag'])] + list(self.streams[stream_type['itag']].items())) for stream_type in self.__class__.stream_types if stream_type['itag'] in self.streams]


def process(cmd, ua, url, cookie = None, page = None, proxy = None):
    if 'youku' not in url:
        return None

    titles = []
    files = []

    stream_id = match1(cmd, 'stream_id=([^&]+)')
    site = Youku()
    site.url = url
    site.prepare()
    site.sort_sream()
    site.extract(stream_id=stream_id)
    
    if not stream_id:
        stream_id = self.streams_sorted[0]['id']

    urls = site.streams[stream_id]['src']

    if len(urls) == 1:
        titles.append(site.title)
        files.append(site.title + '.' + stream_id)
    else:
        i = 0
        for item in urls:
            i += 1
            titles.append(site.title + '_%02d' % i)
            files.append(site.title + ('_%02d.' + stream_id) % i)

    return {"err":0, "title":site.title, "urls":urls, "titles":titles, "files":files}
    
if __name__ == '__main__':
    # site = Youku()
    # site.url = 'http://v.youku.com/v_show/id_XMTY1NjgxMDYxNg==.html'
    # site.prepare()
    # site.sort_sream()
    # site.extract(stream_id = 'mp4')
    # print(site.streams)

    print(process("stream_id=mp4", None, 'http://v.youku.com/v_show/id_XNjkzMzcwODA4.html?f=20277491&ev=24'))
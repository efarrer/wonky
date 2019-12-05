#!/usr/bin/env python

import os
import SocketServer
import BaseHTTPServer
import re, urllib2

def kilobytes(kilo):
  "Return the number of bytes in the given kilobytes"
  return kilo * 1024

def megabytes(meg):
  "Return the number of bytes in the given megabytes"
  return kilobytes(meg) * 1024


class fileCache:
  """
    Caches data in memory
    Old data is flushed to disk when heap usage excedes hardmax limit
    Note that the cache is swapped to disk first in first out
    If an existing object is pushed into the cache the fifo order is *not* updated
  """

  def __init__(self, softmax, hardmax):
    self.cache = {}
    self.softmax = softmax
    self.hardmax = hardmax

  def flush(self):
    "Writes any excess data to disk"
    if self.size > self.hardmax:
      while self.size > self.softmax:
        file = self.queue.pop(0)
        value = self.cache[file]
        self.size -= len(value)
        save(file, value)
        del self.cache[file]

  def put(self, file, data):
    "Adds a file to the cache or replaces it if it exists"
    if self.cache.has_key(file):
      self -= len(self.cache[file])
    else:
      self.queue.append(file)

    self.cache[file] = data
    self.size += len(data)
    flush()

  def get(self, file):
    "Returns a file from the cache or None if it doesn't exist"
    if (self.cache.has_key(file)):
      return self.cache[file]
    else:
      return self.load(file)

  def load(self, file):
    "Loads data from the file cache"
    try:
      f = open("./" + file, "rb")
      data = f.read()
      f.close()
      return data
    except IOError:
      return None

  def save(self, file, data):
    "Saves data to the file cache"
    try:
      (dirs, file) = os.path.split("./" + file)
      os.makedirs(dirs)
    except:
      pass
    try:
      f = open("./" + file + ".bak", "wb")
      f.write(data)
      f.close()
      os.rename("./" + file + ".bak", "./" + file)
    except:
      pass


def theTweak(im):
  "Performs the tweak on an image object"
  import Image, ImageFilter, ImageOps
  #return ImageOps.greyscale( im );
  return im.rotate(180)

def tweakImageData(data):
  "Tweaks image data"
  import Image, StringIO
  inputIO = StringIO.StringIO(data)
  outputIO = StringIO.StringIO()
  im = Image.open(inputIO)
  theTweak(im).save(outputIO, "GIF")
  contents = outputIO.getvalue()
  inputIO.close()
  outputIO.close()
  return contents


#verbose = 0

class WonkyRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
  "Handles wonky requests"

  restr = """
          ^
          [/]      # The opening slash
          ([^/]*)  # The hostname
          (.*)     # The path
          $
          """
  urlre = re.compile(restr, re.VERBOSE)

  def __init__(self):
    self.cache = fileCache(megabytes(5), megabytes(6))

  def do_GET(self):
    urlmatch = self.urlre.match(self.path)
    host = urlmatch.group(1)
    file = urlmatch.group(2)
    print("Host: " + host)
    print("File: " + file)
    tweaked = self.cache.get(host + file)
    if tweaked:
      print("Cached!!!")
    else:
      print('http://' + host + file);
      try:
        request = urllib2.urlopen('http://' + host + file)
        tweaked = tweakImageData(request.read())
      except urllib2.HTTPError:
        self.send_response(404)
        return

    self.send_response(200)
    self.send_header('Content-type', 'image/gif')
    self.send_header('Content-length', len(tweaked))
    self.end_headers()
    self.wfile.write(tweaked)

try:
  httpd = SocketServer.ThreadingTCPServer(('', 8080), WonkyRequestHandler)
  httpd.serve_forever()
except:
  print "\nBuBye"


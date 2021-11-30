#!/usr/bin/env python3

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2021, Jan Grashoefer

import sys
import threading

import ssl
import urllib.request
import urllib.parse
import xml.etree.ElementTree as ET
import hashlib

from argparse import ArgumentParser, FileType
from getpass import getpass

class FritzSession:
	"""
	Class to manage a FRITZ!OS WebGUI session

	This class is based on the example code provided by AVM at https://avm.de/service/schnittstellen/.
	A session is maintained using a SID obtained in a challenge-response process.
	By default the PBKDF2 based challenge response algorithm is used,
	falling back to MD5 for older FRITZ!OS versions.

	Note: SSL certificates are not validated by default as FRITZ!Boxes typically use
	self signed certificates.
	"""

	LOGIN_SID_ROUTE = "/login_sid.lua?version=2"
	class LoginState:
		def __init__(self, challenge: str, blocktime: int, last_user: str):
			self.challenge = challenge
			self.blocktime = blocktime
			self.last_user = last_user
			self.is_pbkdf2 = challenge.startswith("2$")

	class LoginFailed(Exception):
		""" FritzSession login failed. """
		pass

	def __init__(self, box_url: str, ssl_context: ssl.SSLContext = None):
		self.box_url = box_url
		self.ssl_context = ssl_context
		self.sid = ""

	def login(self, username: str, password: str) -> str:
		try:
			state = self.__get_login_state()
		except Exception as ex:
			raise FritzSession.LoginFailed("failed to get challenge") from ex

		if state.blocktime > 0:
			raise FritzSession.LoginFailed(f"login blocked for {state.blocktime} seconds")

		if state.is_pbkdf2:
			challenge_response = self.__calculate_pbkdf2_response(state.challenge, password)
		else:
			challenge_response = self.__calculate_md5_response(state.challenge, password)

		user = username if username != None else state.last_user
		try:
			sid = self.__send_response(user, challenge_response)
		except Exception as ex:
			raise FritzSession.LoginFailed("failed to send challenge response") from ex
		if sid == "0000000000000000":
			raise FritzSession.LoginFailed("wrong username or password")

		self.sid = sid
		return sid

	def logout(self):
		post_data_dict = {"sid":self.sid, "logout":""}
		post_data = urllib.parse.urlencode(post_data_dict).encode()
		headers = {"Content-Type":"application/x-www-form-urlencoded"}
		url = self.box_url + FritzSession.LOGIN_SID_ROUTE
		# Request logout
		http_request = urllib.request.Request(url, post_data, headers)
		urllib.request.urlopen(http_request, context=self.ssl_context)

	def __get_login_state(self): #-> FritzSession.LoginState:
		""" Get login state from FRITZ!Box """
		url = self.box_url + FritzSession.LOGIN_SID_ROUTE
		http_response = urllib.request.urlopen(url, context=self.ssl_context)
		xml = ET.fromstring(http_response.read())

		challenge = xml.find("Challenge").text
		blocktime = int(xml.find("BlockTime").text)
		# Get the last logged in user if available
		user_xml = xml.find("Users/User[@last='1']")
		last_user = "" if user_xml is None else user_xml.text

		return FritzSession.LoginState(challenge, blocktime, last_user)

	def __calculate_pbkdf2_response(self, challenge: str, password: str) -> str:
		""" Calculate the response for a given challenge via PBKDF2 """
		challenge_parts = challenge.split("$")
		# Extract all necessary values encoded into the challenge
		iter1 = int(challenge_parts[1])
		salt1 = bytes.fromhex(challenge_parts[2])
		iter2 = int(challenge_parts[3])
		salt2 = bytes.fromhex(challenge_parts[4])
		# Hash twice, once with static salt...
		hash1 = hashlib.pbkdf2_hmac("sha256",password.encode(),salt1,iter1)
		# Once with dynamic salt.
		hash2 = hashlib.pbkdf2_hmac("sha256",hash1,salt2,iter2)
		return f"{challenge_parts[4]}${hash2.hex()}"

	def __calculate_md5_response(self, challenge: str, password: str) -> str:
		""" Calculate the response for a challenge using legacy MD5 """
		response = challenge + "-" + password
		# the legacy response needs utf_16_le encoding
		response = response.encode("utf_16_le")
		md5_sum = hashlib.md5()
		md5_sum.update(response)
		response = challenge + "-" + md5_sum.hexdigest()
		return response

	def __send_response(self, username: str, challenge_response: str) -> str:
		""" Send the response and return the parsed sid. raises an Exception on error """
		# Build response params
		post_data_dict = {"username":username, "response":challenge_response}
		post_data = urllib.parse.urlencode(post_data_dict).encode()
		headers = {"Content-Type":"application/x-www-form-urlencoded"}
		url = self.box_url + FritzSession.LOGIN_SID_ROUTE
		# Send response
		http_request = urllib.request.Request(url, post_data, headers)
		http_response = urllib.request.urlopen(http_request, context=self.ssl_context)
		# Parse SID from resulting XML.
		xml = ET.fromstring(http_response.read())
		return xml.find("SID").text


class FritzCapture:
	"""
	Class to run a packet capture on a FRITZ!Box

	After start()-ing the capture, download() uses a thread to write the data into the output_file.
	Use stop() to terminate the download gracefully.
	"""
	BUFFER_SIZE = 4*1024

	class CaptureFailed(Exception):
		""" FritzSession login failed. """
		pass

	def __init__(self, fritz_url, fritz_sid, fritz_if, output_file, ssl_ctx):
		self.fritz_url = fritz_url
		self.fritz_sid = fritz_sid
		self.fritz_if = fritz_if
		self.ssl_ctx = ssl_ctx
		self.output_file = output_file
		self.running = False

	def start(self):
		url = f"{self.fritz_url}/cgi-bin/capture_notimeout?sid={self.fritz_sid}&capture=Start&snaplen=1600&ifaceorminor={self.fritz_if}"
		try:
			self.cap_response = urllib.request.urlopen(url, context=self.ssl_ctx)
			self.running = True
		except Exception as ex:
			raise FritzCapture.CaptureFailed("failed to request capture start") from ex

	def stop(self):
		url = f"{self.fritz_url}/cgi-bin/capture_notimeout?sid={self.fritz_sid}&capture=Stop&ifaceorminor={self.fritz_if}"
		try:
			urllib.request.urlopen(url, context=self.ssl_ctx)
			self.running = False
		finally:
			self.download_thread.join(3)

	def __download(self):
		while True:
			buffer = self.cap_response.read(FritzCapture.BUFFER_SIZE)
			if not buffer:
				break
			try:
				self.output_file.write(buffer)
				self.output_file.flush()
			except IOError:
				# Broken pipes don't leave captures dangling
				break

	def download(self):
		self.download_thread = threading.Thread(target=self.__download, daemon=True)
		self.download_thread.start()
		self.download_thread.join()


def get_arguments():
	parser = ArgumentParser(description='This script obtains a packet capture from a given FRITZ!Box.')
	parser.add_argument('-f', metavar='URL', type=str, default='https://fritz.box',
		dest='url', help='URL of the FRITZ!Box [https://fritz.box]')
	parser.add_argument('-u', metavar='USER', type=str,
		dest='user', help='username to login with [last user logged in]')
	parser.add_argument('-p', metavar='PASSWORD', type=str,
		dest='password', help='password to login with')
	parser.add_argument('-o', metavar='FILE', type=FileType('wb'), default=sys.stdout.buffer,
		dest='out_file', help='output file [stdout]')
	parser.add_argument('-i', metavar='INTERFACE', type=str, default='1-lan',
		dest='interface', help='interface to capture [1-lan]')
	parser.add_argument('--check-cert', action='store_true', default=False,
		dest='check_cert', help='enable certificate check (disabled by default due to self-signed FRITZ!Box certificates)')
	parser.add_argument('--debug', action='store_true', default=False,
		dest='debug', help='enable debug mode')
	return parser.parse_args()


def eprint(*args, **kwargs):
	print(*args, file=sys.stderr, **kwargs)


def main():
	args = get_arguments()

	debug = args.debug
	output_file = args.out_file
	fritz_url = args.url
	fritz_user = args.user
	fritz_pw = args.password
	fritz_if = args.interface
	ssl_ctx = ssl.create_default_context() if args.check_cert else ssl._create_unverified_context()

	eprint(f"Capturing of \"{fritz_if}\" from FRITZ!Box at \"{fritz_url}\"")
	if not fritz_pw:
		try:
			fritz_pw = getpass()
		except KeyboardInterrupt:
			return 0
		except Exception as e:
			if debug: raise e
			return 1

	session = FritzSession(fritz_url, ssl_ctx)
	try:
		sid = session.login(fritz_user, fritz_pw)
		if debug:
			eprint(f"Logged in using SID={sid}")

		capture = FritzCapture(fritz_url, sid, fritz_if, output_file, ssl_ctx)
		capture.start()
		capture.download()
	except FritzSession.LoginFailed as e:
		eprint(f"Login to FRITZ!Box failed: {e}")
		if debug: raise e
		return 2
	except FritzCapture.CaptureFailed as e:
		eprint(f"Starting capture failed: {e}")
		if debug: raise e
		return 3
	except Exception as e:
		eprint(f"Unexpected exception: {e}")
		if debug: raise e
		return 4
	except KeyboardInterrupt:
		if capture is not None and capture.running:
			eprint("\nStopping capture...")
			capture.stop()
	finally:
		session.logout()

	# Trigger final flush on stdout and ignore broken pipes
	try:
		sys.stdout.close()
	except IOError as e:
		pass


if __name__ == "__main__":
	main()

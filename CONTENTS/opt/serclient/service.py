#!/usr/bin/env python
# encoding: utf-8
#
# ExtraControl - Aruba Cloud Computing ExtraControl
# Copyright (C) 2012 Aruba S.p.A.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys
import os
import argparse
import logging
import serial
import struct
import binascii
import base64
from elementtree import ElementTree as et
import threading
import subprocess
from Queue import Queue
import time
import glob
from xml.sax.saxutils import unescape, escape
from tools import * # pylint: disable=W0614,W0401
import shlex
import tempfile
#import string
import pickle
import datetime

# packet type
COMMAND = "COMMAND"
ACK = "ACK"
RECEIVED = "RECEIVED"
AUTHRESPONSE = "AUTHRESPONSE"
RESPONSE = "RESPONSE"

# mn, 30 byte command, 32 byte guid, 16 byte for late use, 4 byte packet number, 4 byte packet count, 4 byte body size
PROTOCOL_HEADER = "<c30s32sII16sI"
PROTOCOL_HEADER_SIZE = struct.calcsize(PROTOCOL_HEADER)
HEADER_MAGIC_NUMBER = "\x02"

# crc32, mn
PROTOCOL_FOOTER = "<Ic"
PROTOCOL_FOOTER_SIZE = struct.calcsize(PROTOCOL_FOOTER)
FOOTER_MAGIC_NUMBER = "\x03"

PACKET_MIN_SIZE = PROTOCOL_HEADER_SIZE + PROTOCOL_FOOTER_SIZE
SERIAL_MIN_READ = 100000
IDLE_TIMEOUT    = 60 * 15

# debug
N_DEBUG_REQUEST = 1
N_DEBUG_FAKE_REQUESTS = False

# commands other than plugin/external:
INTERNAL_COMMANDS = (
	'systemstatus history',
	'systemstatus monitorstart',
	'systemstatus monitorstop',
	'systemstatus retentiontime',
	'systemstatus deletehistory',
	'systemstatus monitorconf'
)

# avoids using deprec. 'string' module:
HEXDIGITS = '0123456789abcdefABCDEF'

class Packet(object):
	"""
	Simple class to serialize/deserialize a packet to/from string
	"""

	def __init__(self, guid, ptype, body="", number=1, count=1):
		assert ptype in (COMMAND, ACK, RECEIVED, AUTHRESPONSE, RESPONSE), "Unrecognize packet type: %r" % ptype
		assert isinstance(guid, str) and len(guid) == 32, "Packet id is required to be a string of len 32"
		assert number <= count, "Packet number is bigger than packet count"
		self.guid = guid
		self.type = ptype
		self.body = body
		self.number = number
		self.count = count

	def _toStringNoFooter(self):
		return struct.pack(
			PROTOCOL_HEADER,
			HEADER_MAGIC_NUMBER,
			self.type,
			self.guid,
			self.number,
			self.count,
			"",
			len(self.body)
		) + self.body

	def toString(self):
		hb = self._toStringNoFooter()
		crc = binascii.crc32(hb) & 0xffffffff
		f = struct.pack(PROTOCOL_FOOTER, crc, FOOTER_MAGIC_NUMBER)
		return hb + f

	def isSinglePacket(self):
		return self.number == 1 and self.count == 1

	def __len__(self):
		return PROTOCOL_HEADER_SIZE + len(self.body) + PROTOCOL_FOOTER_SIZE

	def __repr__(self):
		if len(self.body) > 300:
			return "Packet(guid=%r, ptype=%r, body=%r ..., number=%d, count=%d)" % (
				self.guid,
				self.type,
				self.body[:300],
				self.number, self.count
			)
		return "Packet(guid=%r, type=%r, body=%r, number=%d, count=%d)" % (
			self.guid,
			self.type,
			self.body,
			self.number,
			self.count
		)

	def crc(self):
		crc = binascii.crc32(self._toStringNoFooter()) & 0xffffffff
		return crc

	@staticmethod
	def unpackHeader(_buffer):
		# TODO: PLEASE use named tuple to unpack the struct
		mn, t, guid, packet_number, packet_count, _, bs = struct.unpack(
			PROTOCOL_HEADER,
			_buffer[:PROTOCOL_HEADER_SIZE]
		)
		t = t.split('\x00')[0]
		return mn, bs, t, guid, packet_number, packet_count

	@staticmethod
	def unpackFooter(string):
		crc, mn = struct.unpack(PROTOCOL_FOOTER, string[:PROTOCOL_FOOTER_SIZE])
		return crc, mn

	@staticmethod
	def fromString(string):
		_, bs, t, i, packet_number, packet_count = Packet.unpackHeader(string)
		b = string[PROTOCOL_HEADER_SIZE : PROTOCOL_HEADER_SIZE + bs]
		f = string[PROTOCOL_HEADER_SIZE + bs : PROTOCOL_HEADER_SIZE + bs + PROTOCOL_FOOTER_SIZE]
		p = Packet(i, t, b, packet_number, packet_count)
		crc, mn = Packet.unpackFooter(f)
		if mn != FOOTER_MAGIC_NUMBER:
			raise ValueError("end of packet not found")
		if crc != p.crc():
			raise ValueError("%x != %x" % (crc, p.crc()))
		return p

	@staticmethod
	def hasPacketHeader(string):
		return len(string) >= PROTOCOL_HEADER_SIZE

	@staticmethod
	def hasValidPacketHeader(_buffer):
		mn, body_size, t, guid, pn, pc = Packet.unpackHeader(_buffer)
		return (mn == HEADER_MAGIC_NUMBER) and \
			(t in (COMMAND, ACK, RECEIVED, AUTHRESPONSE, RESPONSE)) and \
			(pn <= pc) and \
			not(False in map(lambda k: k in HEXDIGITS, guid))

	@staticmethod
	def hasPacketBodyAndFooter(string):
		_, bs, _, _, _, _ = Packet.unpackHeader(string)
		return len(string) >= (PROTOCOL_HEADER_SIZE + bs + PROTOCOL_FOOTER_SIZE)

	@staticmethod
	def newWithACK(guid):
		return Packet(guid=guid, ptype=ACK)

	@staticmethod
	def newWithCOMMAND(guid, command, data=None):
		if data == None:
			cmd = "<command><commandString>%s</commandString></command>" % escape(command)
		else:
			data = base64.b64encode(data)
			cmd = "<command><commandString>%s</commandString><binaryData>%s</binaryData></command>" % (escape(command), data)
		return Packet(guid=guid, ptype=COMMAND, body=cmd)

	@staticmethod
	def newWithRECEIVED(guid, number=1, count=1, timeout=False):
		if timeout:
			body = "<responseType>TimeOut</responseType>"
		else:
			body = "<responseType>Success</responseType>"
		return Packet(guid=guid, ptype=RECEIVED, body=body, number=number, count=count)

	@staticmethod
	def newWithAUTHRESPONSE(guid):
		return Packet(guid=guid, ptype=AUTHRESPONSE)

	@staticmethod
	def newWithRESPONSE(guid, response_type, command_name="", output_string="",
		return_code=0, result_message=""
	):
		assert response_type in ("Success", "Error", "TimeOut"), "Response type '%s' not supported" % response_type
		# todo: use elementree
		rt = "<responseType>%s</responseType>" % response_type
		rc = "<resultCode>%d</resultCode>" % return_code
		if result_message == None: result_message = ""
		rm = "<resultMessage>%s</resultMessage>" % escape(result_message)
		cn = "<commandName>%s</commandName>" % escape(command_name)
		if output_string == None: output_string = ""
		_os = "<outputString>%s</outputString>" % escape(output_string)
		body = "<response>" + rt + rc + rm + cn + _os + "</response>"
		return Packet(guid=guid, ptype=RESPONSE, body=body)

class Command(object):
	"""
	Simple class that store the logic behind a COMMAND request.
	"""

	def __init__(self, command, guid, binary_data, monitor=None):
		"""
		@param command: command as extracted from the PACKET
		@param guid: PACKET guid
		"""
		split = shlex.split(command)
		self.command = command
		self.guid = guid
		self.binary_data = binary_data
		self.monitor = monitor # <Monitoring>
		module_name = os.path.basename(split[0])
		self.cmd_line = None
		for _type, upgradable, dirs in MODULE_TYPES.values(): # pylint: disable=W0612
			if _type == MODULE_CUSTOMS:
				# custom module must be called using 'exec script'
				continue
			self.module = moduleFromNameAndType(module_name, _type)
			if self.module:
				self.cmd_line = [self.module.fullPath()] + split[1:]
				if self.binary_data:
					self.cmd_line.extend([self.binary_data])
				break

	def __repr__(self):
		return "Command(%r, %r, %r)" % (self.command, self.guid, self.binary_data)

	def isValid(self):
		"""
		Return True if the command refers to a proper one available
		on the file system
		"""
		return self.module != None

	def isBlocking(self):
		"""
		Returns True if the command is valid and blocking.
		"""
		if self.module == None: return False
		return self.module.isBlocking()

	def spawn(self, timeout, service):
		"""
		Returns a CommandObserver that takes care of spawning and
		controlling the process .
		"""
		return CommandObserver(self, timeout, service, monitor=self.monitor)

	def useServiceAsPythonInterpreter(self):
		return self.module.type() in [MODULE_INTERNALS, MODULE_PLUGINS] and self.module.isPythonScript()

	def isUpdateSoftware(self):
		return self.command.startswith('updateSoftware')

	def moduleName(self):
		"""
		Return the module name as seen from the user (ie restat,
		updateSoftware, remove..)
		"""
		return self.module.aliasName()

class CommandObserver(threading.Thread):
	"""
	Simple class that spawn and observe the running process.

	The process itself is spawned by a secondary thread that is join-ed with
	a timeout by this one. This is used to implement a timeout on the process
	itself.	Process stdout and stderr are merged together.
	"""

	def __init__(self, command, timeout, service, monitor=False, *args, **kwargs):
		assert isinstance(command, Command), "object of type Command expected"
		threading.Thread.__init__(self, *args, **kwargs)
		self._command = command
		self._service = service
		self._process = None
		self._timeout = timeout
		self._kill = False
		self.return_code = 0
		self.timedout = 0
		self.output = ""
		self.monitor = monitor # <Monitoring>
		self.monitoring_collection = False

	def run(self):
		"""
		Handle the generic external command
		"""
		# first we don't want to execute an arbitrary script/command,
		# just the ones we have selected
		if self._command.module == None:
			logger.info("[%s] Command not found '%s'" % (
					self._command.guid, self._command.command
				)
			)
			self.return_code = 1
			self.output = "Command not found"
			self._service.sendLater(
				Packet.newWithAUTHRESPONSE(self._command.guid)
			)
			return

		logger.info("[%s] Running '%r' with timeout %d sec" % (
				self._command.guid, self._command.module, self._timeout
			)
		)

		# if the external command is an internal/plugin python script we use ourself as python interpreter
		if self._command.useServiceAsPythonInterpreter():
			logger.debug("[%s] Python script detected, using service as python interpreter" % (
				self._command.guid)
			)
			cmd_line = [getPythonBin(), '--exec'] + self._command.cmd_line
			if not IS_FROZEN and IS_WINDOWS:
				# In this case we cant Popen .py script because we still need
				# an interpreter to be used
				cmd_line = [sys.executable] + cmd_line
			logger.debug("[%s] >> %r" % (self._command.guid, cmd_line))
		else:
			cmd_line = self._command.cmd_line
		logger.debug('CommandObserver:run -> cmd_line = %s' % cmd_line)

		if self._command.command == 'systemstatus history':
			def target():
				logger.debug('commandObserver.target() history MODE')
				self.output = ''.join(self.monitor.getHistory())
				self.return_code = 0

		elif self._command.command == 'systemstatus monitorstart':
			def target():
				logger.debug('commandObserver.target() monitorstart MODE')
				if self.monitor.getStatus():
					logger.warning('monitoring is already enabled')
					self.output = 'Warning: monitoring is already enabled'
					self.return_code = 0
				else:
					try:
						self.monitor.monitorStart()
						self.output = 'Monitoring successfully started'
						self.return_code = 0
					except Exception:
						logger.error("Monitoring couldn't be started")
						self.output = "Error: Monitoring couldn't be started"
						self.return_code = 1

		elif self._command.command == 'systemstatus monitorstop':
			def target():
				logger.debug('commandObserver.target() monitorstop MODE')
				if not self.monitor.getStatus():
					logger.warning('monitoring is already disabled')
					self.output = 'Warning: monitoring is already disabled'
					self.return_code = 0
				else:
					try:
						self.monitor.monitorStop()
						self.output = 'Monitoring successfully stopped'
						self.return_code = 0
					except Exception:
						logger.error("Monitoring couldn't be stopped")
						self.output = "Error: Monitoring couldn't be stopped"
						self.return_code = 1

		elif self._command.command.startswith('systemstatus retentiontime'):
			def target():
				logger.debug('commandObserver.target() retentiontime MODE')
				# retention time is not optional:
				rtime = int(self._command.command.split()[2])
				try:
					self.monitor.setRetentionTime(rtime)
					self.output = 'Monitoring retention time successfully set to: %s days' % (str(rtime))
					self.return_code = 0
				except Exception, rte:
					logger.error("Monitoring retention time couldn't be set: %s" % str(rte))
					self.output = "Error: monitoring retention time couldn't be set: %s" % str(rte)
					self.return_code = 1

		elif self._command.command.startswith('systemstatus deletehistory'):
			def target():
				logger.debug('commandObserver.target() deletehistory MODE')
				# optional 'datetime' arg detection:
				_oth = None
				_oth_msg = ''
				try:
					_oth = self._command.command.split()[2]
				except IndexError:
					pass
				if _oth:
					_oth_msg = 'up to %s' % str(_oth)

				try:
					self.monitor.deleteHistory(olderthan=_oth)
					logger.debug('Monitoring history deleted %s' % _oth_msg)
					self.output = "Monitoring history deleted %s" % _oth_msg
					self.return_code = 0
				except Exception, dmh:
					logger.debug('Problems occured while deleting monitoring history: %s' % str(dmh))
					self.output = 'Problems occured while deleting monitoring history: %s' % str(dmh)
					self.return_code = 1

		elif self._command.command == 'systemstatus monitorconf':
			def target():
				logger.debug('commandObserver.target() monitorconf MODE')
				self.output = ''.join(self.monitor.getMonitorConf())
				self.return_code = 0
		else:
			def target():
				logger.debug('commandObserver.target() normal MODE')
				try:
					self._process = runExternal(
						cmd_line,
						close_handles=self._command.isUpdateSoftware()
					)
					self.output, _ = self._process.communicate()
				except OSError, oe:
					logger.debug("error executing command: %s" % oe)
					self.output = str(oe)
					del oe

		thread = threading.Thread(target=target)
		thread.start()

		# watch the process and for the request to kill it
		start_time = time.time()
		while (time.time() - start_time) < self._timeout:
			thread.join(0.5)
			if thread.isAlive() == False or self._kill == True: break

		if thread.isAlive():
			if self._kill == False:
				# in this case we don't log it to avoid misunderstandings
				logger.error("[%s] process timeout" % self._command.guid)
			self._process.terminate()
			thread.join()
			self.timedout = True
		else:
			self.timedout = False

		# remove the restart token because it means it didnt work
		getRestartGUID(remove=True)

		# read the output of the failed updateSoftware command (we should have been killed if the attempt was a success)
		if self._command.isUpdateSoftware():
			self.output = getUpdateSoftwareLOG(remove=True)
			logger.debug("Detected failed updateSoftware attempt with log:\n%s" % self.output)

		if self._kill: return

		if isInternalCommand(self._command.command):
			pass
		elif self._process != None:
			if self._process.returncode != 0:
				logger.debug("[%s] Non-zero exit status for command: %s" % (
					self._command.guid, self._command.command
					)
				)
			else:
				logger.debug("[%s] Command completed." % self._command.guid)
			self.return_code = self._process.returncode
		else:
			# oserror exception
			self.return_code = 1

		if self.monitoring_collection:
			logger.debug('COLLECTION MODE, not returning pkt, just storing\n')
			xml = et.fromstring(self.output)
			dt = xml.find('datetime').attrib['value']

			self.monitor.datastore.addKey(
				dt, # use datetime as a key for easy sorting
				self.output
			)
			logger.debug('stored collected monitoring data')
		else:
			# Normal request mode and history request mode:
			logger.debug('NORMAL reply mode: sendLater AUTHRESPONSE pkt')
			self._service.sendLater(Packet.newWithAUTHRESPONSE(self._command.guid))

	def responsePacket(self):
		"""
		Return a packet of type RESPONSE properly filled with the process
		return code and output.
		"""
		_rm = ""
		_os = ""
		if self.timedout:
			_rt = "TimeOut"
		elif self.return_code == 0:
			_rt = "Success"
			_os = self.output
		else:
			_rt = "Error"
			_rm = self.output

		p = Packet.newWithRESPONSE(guid=self._command.guid,
			response_type=_rt,
			command_name=self._command.command,
			output_string=_os,
			return_code=self.return_code,
			result_message=_rm)
		return p

	def kill(self):
		"""
		Kill the current process and watcher. Can not be called from the
		process thread.
		"""
		self._kill = True
		self.join()

class ReplyResponseObserver(object):
	"""
	Simple class to delivery a Response Packet without breaking the
	CommandObserver interface.
	"""
	def __init__(self, response):
		self._response = response

	def responsePacket(self):
		return self._response

class MonitoringDataStore(object):
	"""
	Simple wrapper to a dictionnary object, encapsulate OS / Distro specific
	parts.
	"""

	def __init__(self, do_open=True):
		self._datastore_path = None # depends on OS/distro
		self._storefile_h = None # file handle
		self._store_d = None # dictionnary
		self._lock = threading.Lock()

		# keep a way to manually control this to ease testing:
		if do_open:
			self._open()

	def _freenas_setroot_ro(self, die_on_error=True):
		o = subprocessCheckOutput(['mount', '-ur', '/'])
		if len(o) > 0 and die_on_error:
			raise RuntimeError('Attempt to set root FS in r/o mode failed: %s' % o)
		return True

	def _freenas_setroot_rw(self, die_on_error=True):
		o = subprocessCheckOutput(['mount', '-uw', '/'])
		if len(o) > 0 and die_on_error:
			raise RuntimeError('Attempt to set root FS in r/w mode failed: %s' % o)
		return True

	def _create_store(self):
		"""
		Creates datastore (pickle) file if not existing yet. This is
		initialized	with an empty dictionnary.
		"""
		if not os.path.exists(self._datastore_path):
			self._store_d = {}

			self._lock.acquire()

			# FreeNAS is now having a R/O rootfs by default, deal with that:
			if isFreeNAS():
				self._freenas_setroot_rw()

			self._storefile_h = open(self._datastore_path, 'wb')
			pickle.dump(self._store_d, self._storefile_h)
			self._storefile_h.close()

			if isFreeNAS():
				self._freenas_setroot_ro(die_on_error=False)

			self._lock.release()
			logger.debug('Created new monitoring datastore')

	def _open(self):
		"""
		Makes the store available for use. Create it if needed.
		"""
		if isWindows():
			# TODO: try other other locations if current part too small or restricted
			self._datastore_path = os.path.join(
				os.getcwd(),
				'datastore',
				'monit_ds.pck'
			)

		elif isLinux():
			self._datastore_path = '/var/lib/serclient/monit_ds.pck'
		elif isFreeNAS(): # BSD based
			# don't use /var, it's wiped out at every reboot/upgrades:
			self._datastore_path = '/conf/base/var/serclient/monit_ds.pck'
			self._freenas_setroot_rw()

		elif isBsd(): # plain BSD, pfSense et al
			self._datastore_path = '/var/serclient/datastore/monit_ds.pck'
		else:
			raise Exception('Unsupported platform')

		# store dir doesn't exist, create it:
		if not os.path.exists(os.path.dirname(self._datastore_path)):
			os.makedirs(os.path.dirname(self._datastore_path))

		# delete possibly empty store file, this won't be loadable:
		if os.path.exists(self._datastore_path):
			if os.stat(self._datastore_path).st_size == 0:
				if isFreeNAS():	self._freenas_setroot_rw()
				os.remove(self._datastore_path)
				logger.debug("Removing invalid datastore file: %s" % str(
					self._datastore_path)
				)

		# create blank store if none exists:
		if not os.path.exists(self._datastore_path):
			self._create_store()

		# now load it, blank or not:
		self._storefile_h = open(self._datastore_path, 'rb')
		self._store_d = pickle.load(self._storefile_h)
		self._storefile_h.close()
		if isFreeNAS():	self._freenas_setroot_ro(die_on_error=False)

	def addKey(self, k, v, overwrite=False):
		if self.hasKey(k) and not overwrite:
			raise RuntimeError('Monitoring datastore key: %s already exists, and overwriting is disabled' % str(k))
		else:
			self._store_d[k] = v

		self._lock.acquire()

		if isFreeNAS():	self._freenas_setroot_rw()
		self._storefile_h = open(self._datastore_path, 'wb')
		pickle.dump(self._store_d, self._storefile_h)
		self._storefile_h.close()
		if isFreeNAS():	self._freenas_setroot_ro(die_on_error=False)

		self._lock.release()

	def delKey(self, k):
		if not self.hasKey(k):
			raise ValueError('Monitoring datastore has no such key: %s' % str(k))

		self._lock.acquire()

		if isFreeNAS():	self._freenas_setroot_rw()
		self._storefile_h = open(self._datastore_path, 'wb')
		dummy = self._store_d.pop(k)
		pickle.dump(self._store_d, self._storefile_h)
		self._storefile_h.close()
		if isFreeNAS():	self._freenas_setroot_ro(die_on_error=False)

		self._lock.release()

	def getKey(self, k):
		self._lock.acquire()

		self._storefile_h = open(self._datastore_path, 'rb')
		self._store_d = pickle.load(self._storefile_h)
		self._storefile_h.close()

		if k in self._store_d.keys():
			self._lock.release()
			return self._store_d[k]

		self._lock.release()
		return None

	def getKeys(self):
		return self._store_d.keys()

	def hasKey(self, k):
		self._lock.acquire()

		self._storefile_h = open(self._datastore_path, 'rb')
		self._store_d = pickle.load(self._storefile_h)
		self._storefile_h.close()

		if k in self._store_d.keys():
			self._lock.release()
			return True

		self._lock.release()
		return False

class Monitoring(object):
	"""
	Monitoring data collection management.
	"""

	def __init__(self, service):
		"""
		Initialize object to proper values, managing persistence when possible.
		"""
		self.enabled = None # bool, only enable explicitly
		self.interval = 180 # int, in seconds, default is 180(3 minutes)
		self.retention_time = 1 # int, default is 1 day
		self.datastore = None # <MonitoringDataStore>
		self.lastruntime = None # datetime
		self._service = service # <Service>
		# iterations to wait before attempting outdated history data purge:
		self._oldhist_itercount = 600 # int, main loop
		self._oldhist_inc = 0 # int

	def __del__(self):
		if self.datastore:
			self._storeMonitorConf()

	def _storeMonitorConf(self):
		"""
		Make configuration values persistent, this is stored in a special
		key: 'monitorconf' in the datastore.
		"""

		self.datastore.addKey(
			'monitorconf', # k
			{
				'enabled': self.enabled,
				'retention_time': self.retention_time,
				'lastruntime': self.lastruntime,
			}, # v - store conf as a dictionnary
			overwrite=True
		)

	def monitorStart(self, interval=None):
		"""
		Enable, and start monitoring data collection.

		@param interval: Integer. Interval in seconds between collects. Defaults
		                 to 180 seconds.
		"""
		self.enabled = True
		self.datastore = MonitoringDataStore()

		if interval:
			assert isinstance(interval, int), 'Monitoring interval value must be a positive integer'
			assert (interval > 0), 'Monitoring interval value must be a positive integer'
			# interval is intentionally volatile. If not specified during
			# a start/restart, the default value (see __init__) is used.
			# Could be changed easily however.
			self.interval = interval
			logger.debug('Monitoring interval set to %s' % str(self.interval))

		# if no stored conf, create a new one:
		if not self.datastore.hasKey('monitorconf'):
			logger.debug('Exisiting store is missing a monitorconf key, creating it')
			self._storeMonitorConf()

		else:
			# re-use stored conf:
			_storedconf = self.datastore.getKey('monitorconf')
			self.retention_time = _storedconf['retention_time']
			self.lastruntime = _storedconf['lastruntime']
			logger.debug('Using previous monitoring configuration values')

		# check everything's allright
		if not self.datastore.hasKey('monitorconf'):
			raise RuntimeError('unable to create a monitorconf key in datastore')

	def monitorStop(self):
		"""
		Stop and disable monitoring data collection.
		"""
		if self.enabled:
			self.enabled = False
			self._storeMonitorConf()
			self.datastore = None

	def setRetentionTime(self, days=3):
		"""
		Set the number of days collected data should be kept before being
		purged.

		@param days: Integer, number of days to keep history data.
		"""
		assert isinstance(days, int), "days must be a positive integer"
		assert (days > 0), "days must be a positive integer"

		self.retention_time = days
		self._storeMonitorConf()

	def getHistory(self):
		"""
		Return history of monitoring collected data as a list.
		"""
		o = []
		ak = self.datastore.getKeys()
		for k in ak:
			if k != 'monitorconf':
				o.append(
					str(self.datastore.getKey(k))
				)
		return o

	def deleteOutdatedHistory(self):
		"""
		A wrapper around deleteHistory() intended to be run every 600 iteration
		of the main loop, automatically.
		"""
		if self._oldhist_inc < self._oldhist_itercount:
			self._oldhist_inc += 1
		else:
			bu_time = time.time() - float(86400 * int(self.retention_time))
			self.deleteHistory(
				olderthan=time.strftime("%Y%m%d%H%M%S", time.localtime(bu_time))
			)
			self._oldhist_inc = 0

	def deleteHistory(self, olderthan=None):
		"""
		Force the cancellation of all the history.
		This to be used when receiving a 'systemstatus delete history' command.

		@param olderthan: Optional datetime string in YYYYMMDDHHMMSS format.
		                  Data older than this gets deleted. If omitted takes
		                  the value of 'now'.
		"""
		delall = False
		# get unix time and formatted datetime representations;
		if not olderthan:
			delall = True
			u_time = time.time()
			s_time =  time.strftime("%Y%m%d%H%M%S", time.localtime(u_time))
		else:
			if len(olderthan) != 14:
				raise ValueError('olderthan must be 12 characters long: YYYYMMDDHHMMSS')
			s_time = olderthan
			d = datetime.datetime(
				int(s_time[0:4]),   # year
				int(s_time[4:6]),   # month
				int(s_time[6:8]),   # day
				int(s_time[8:10]),  # hour
				int(s_time[10:12]), # minute
				int(s_time[12:14]), # second
				000000 # unused but needed here
			)
			u_time = time.mktime(d.timetuple())

		logger.debug('Monitoring datastore is %s entries long' % str(len(self.datastore.getKeys())))
		if delall:
			logger.debug('Starting deleting all collected monitoring values')
			for k in self.datastore.getKeys():
				if str(k) == 'monitorconf': continue # ignore our config data
				self.datastore.delKey(k)
		else:
			logger.debug('Starting deleting stored monitoring values older than: %s' % str(s_time))
			for k in self.datastore.getKeys():
				if str(k) == 'monitorconf': continue
				if float(k) < float(s_time):
					#logger.debug('Deleted stored monitoring values for: %s' % k)
					self.datastore.delKey(k)
		logger.debug('Monitoring datastore is %s entries long' % str(len(self.datastore.getKeys())))

	def getMonitorConf(self):
		"""
		Return monitoring configuration values:

		- monitorstatus: 'start' or 'stop'.
		- monitortime: collection interval, in seconds.
		- retentiontime: days to wait before dismiss archived monitoring data.
		"""
		if self.enabled:
			monitorstatus = 'start'
		else:
			monitorstatus = 'stop'

		conf_o = '<systemstatusmonitor>'
		conf_o += '<monitorstatus value="%s"/>' % (monitorstatus)
		conf_o += '<monitortime value="%s"/>' % (self.interval)
		conf_o += '<retentiontime value="%s"/>' % (self.retention_time)
		conf_o += '</systemstatusmonitor>'

		return conf_o

	def getStatus(self):
		"""
		Return True if monitoring collection is enabled, False otherwise.
		"""
		if self.enabled:
			return True
		else:
			# filters possible None or inconsistent values:
			return False

	def collect(self):
		"""
		Perform monitoring data collection, if time interval is reached, do
		nothing otherwise.
		"""
		if not self.lastruntime:
			self._updateLastRunTime()
			logger.debug('Initialized monitoring collect timestamp to: %s ' % str(self.lastruntime))
			return

		now = time.time()
		gap = float(now - self.lastruntime)

		if gap > float(self.interval):
			logger.debug('Starting a new monitoring data collection')
			systemstatus_cmd = Command(
				command="systemstatus",
				guid="00000000000000000000000000000000",
				binary_data="",
				monitor=self
			)

			systemstatus_co = systemstatus_cmd.spawn(
				timeout=40,
				service=self._service,
			)
			systemstatus_co.monitoring_collection = True
			systemstatus_co.run()

			self._updateLastRunTime()
		else:
			pass

	def _updateLastRunTime(self, t=None):
		"""
		Update the 'lastruntime' member with 't' if provided, else use
		time.time().

		@param t: A unix datetime, as produced by time.time().
		"""
		if t:
			self.lastruntime = t
		else:
			self.lastruntime = time.time()
		self._storeMonitorConf()

class Service(object):
	"""
	service class.
	Read from the serial port and manage the commands execution.
	"""

	def __init__(self, args, serial_class=serial.Serial):
		"""
		Create a service instance ready to be used calling -L{start} and
		then -L{run}

		@param args: Arguments from ArgumentParser, are passed to the serial
		             class constructor.
		@param serial_class: Serial class, default to serial.Serial can be
		                     changed for testing purpose. The class must
		                     respond to -B{read} and -B{write}.
		"""
		assert isinstance(args, dict), "args must be a dictionary"
		self._args = args
		self._serial_class = serial_class
		self._buffer = ""
		self._threads = {}
		self._out_queue = Queue()
		self._command_timeout = int(args['PLUGINS']['command_timeout'])
		self._timers = []
		self._command_queue = []
		self._command_queue_process = True
		self._quit = False
		self._packet_pool = dict()
		self._logic_timeout = None
		self._monitor = Monitoring(service=self)
		self._last_data = time.time()
		self.sp = None # <_serial_class>

	def idleTime(self):
		return time.time() - self._last_data

	def send(self, p):
		"""
		Send a packet by writing its string form on the serial port.

		@param p: Instance of packet
		"""
		assert isinstance(p, Packet), "Not a Packet"
		self._last_data = time.time()
		logger.info("Sending packet: %r" % p)
		k = p.toString()
		logger.debug("Writing: %d %r" % (len(k), k))
		tot = len(k)
		if chr(255) in k:
			logger.debug("IAC FOUND")
		done = 0
		# chunk write
		cs = 8192
		while len(k) != 0:
			e = k[:cs]
			k = k[cs:]
			done += len(e)
			logger.debug("Writing to serial port: %d/%d bytes" % (done, tot))
			self.sp.write(e)
			#time.sleep(20)

	def sendLater(self, p):
		"""
		Add the packet in a queue and send it as soon as possible.
		"""
		assert isinstance(p, Packet), "Not a Packet"
		self._out_queue.put(p)

	def addToPacketPool(self, packet):
		"""
		Add a packet in pool of packets for waiting all of them.
		"""
		self._packet_pool.setdefault(packet.guid, dict())[packet.number] = packet
		print self._packet_pool

	def isPacketPoolCompleteForPacket(self, packet):
		"""
		Return True if we have all packets of that group.
		"""
		return len(self._packet_pool.get(packet.guid, dict()).keys()) == packet.count

	def aggregatePacketsFromGUID(self, guid):
		"""
		Merge all packets together in a big huge packet.
		"""
		np = len(self._packet_pool.get(guid, dict()).keys())
		print np
		up = []
		for i in range(1, np+1):
			try:
				p = self._packet_pool.get(guid)[i]
			except KeyError:
				logger.error("Error decoding a sequence of packets: %r" %
					self._packet_pool.get(guid).keys()
				)
				return None
			up.append(p.body)
		return Packet(p.guid, p.type, ''.join(up), np, np)

	def removeFromPacketPoolForGUID(self, guid):
		"""
		Remove and clean the packet pool for the requested guid.
		"""
		del self._packet_pool[guid]

	def read(self, timeout=None):
		"""
		Return a packet received from the serial port or None if timeout is
		elapsed.

		@param timeout: Integer, timeout in seconds
		"""
		started = time.time()
		while 1:
			if timeout and (time.time() - started) > timeout:
				return None
			if Packet.hasPacketHeader(self._buffer):
				if Packet.hasValidPacketHeader(self._buffer):
					if self._logic_timeout == None:
						self._logic_timeout = time.time()
					else:
						if (time.time() - self._logic_timeout) > 30.0:
							logger.debug("LOGIC TIMEOUT detected, looking for new packet")
							_, _, _, guid, pn, pc = Packet.unpackHeader(self._buffer)
							self.send(Packet.newWithRECEIVED(guid, pn, pc, timeout=True))
							self._buffer = self._buffer[1:]
							self._logic_timeout = None
							return None

					if Packet.hasPacketBodyAndFooter(self._buffer):
						logger.debug("Valid footer received")
						try:
							last_packet = Packet.fromString(self._buffer)
							logger.debug("Packet received: %r" % last_packet)
							self._buffer = self._buffer[len(last_packet):]
							if last_packet.isSinglePacket():
								return last_packet
							else:
								# we store this packet in the pool for later aggregation
								self.addToPacketPool(last_packet)
								if self.isPacketPoolCompleteForPacket(last_packet):
									# aggregation
									p = self.aggregatePacketsFromGUID(last_packet.guid)
									# remove
									self.removeFromPacketPoolForGUID(last_packet.guid)
									if p:
										logging.debug("[%r] Aggregate multiple packets" % p.guid)
										return p
								else:
									# send the received packet to keep reading the new ones, at this point
									# we can't check if the XML is valid or the BASE64 data are ok, we wait to
									# have all of them
									self.send(
										Packet.newWithRECEIVED(
											last_packet.guid,
											last_packet.number,
											last_packet.count
										)
									)
						except ValueError, ve:
							logger.critical("Error decoding packet: %s" % ve)
							# todo: send a response with error crc not valid
							self._buffer = self._buffer[1:]
							del ve
					else:
						# wait for more bytes
						p = len(self._buffer)
						v = self.sp.read(SERIAL_MIN_READ)
						self._buffer += v
						if v:
							self._last_data = time.time()
						if p != len(self._buffer):
							logger.debug("Reading: buffer size %d - %r" % (
								len(self._buffer), v)
							)
				else:
					# skip bytes looking for a new magic number
					self._buffer = self._buffer[1:]
					s = 0
					while len(self._buffer) > 0 and self._buffer[0] != chr(0x02) and s < 5000:
						self._buffer = self._buffer[1:]
						s = s + 1
					logger.debug("Header not found: skipped %d byte from read buffer" % s)
			else:
				# wait for more bytes
				self._logic_timeout = None
				p = len(self._buffer)
				v = self.sp.read(SERIAL_MIN_READ)
				self._buffer += v
				if v:
					self._last_data = time.time()
				if p != len(self._buffer):
					logger.debug("Reading: buffer size %d - %r" % (
						len(self._buffer), v)
					)

	def start(self):
		"""
		Start the service by opening the serial port.
		"""
		logger.info("Opening serial")
		c = self._args['SERIAL']
		if c['port'] == '0':
			port = 0
		else:
			port = c['port']
		try:
			self.sp = self._serial_class(port=port,
										 baudrate=c['baudrate'],
										 bytesize=int(c['bytesize']),
										 parity=c['parity'],
										 stopbits=float(c['stopbits']),
										 timeout=1)

		except AttributeError:
			# happens when the installed pyserial is older than 2.5. use the
			# Serial class directly then.
			logger.critical("Serial attribute Error")
		logger.info("Serial port open with success: %r", self.sp)

	def run(self, check=lambda: 1):
		"""
		Start reading from serial port managing any requested command.
		"""
		logger.info("Service version: %s" % getServiceVersion())
		# Recovering from a restart ?
		rg = getRestartGUID(remove=True)
		if rg != None:
			logger.info("Sending restart/updateSofware response")
			t = getUpdateSoftwareLOG(remove=True)
			p = Packet.newWithAUTHRESPONSE(rg)
			self._threads[p.guid] = ReplyResponseObserver(
				Packet.newWithRESPONSE(p.guid, "Success", "", t)
			)
			self.send(p)

		self._monitor.monitorStart()

		# we store the number of threads before starting accepting any requer
		# because we monitor its value to undertand when a blocking task can start
		# Normal values is 1 but under windows services its 2.
		base_threads = threading.activeCount()
		while not self._quit and check():
			# read from the serial waiting for a packer or timeout
			p = self.read(timeout=1.0)

			if p:
				self.processPacket(p)
			elif self.idleTime() > IDLE_TIMEOUT:
				self.send(Packet.newWithACK(guidFromInt(0)))
			# process AUTHRESPONSE commands generated by running threads
			while not self._out_queue.empty():
				p = self._out_queue.get()
				self.send(p)
				#self._out_queue.task_done()
			# are all done ?
			done = threading.activeCount() == base_threads
			# if all done and the queue processig is stopped we can restart it
			if done and self._command_queue_process == False:
				self._command_queue_process = True
				logger.debug("Leaving blocking mode")
			# if enabled, process queued COMMAND
			if self._command_queue_process == True:
				while self._command_queue:
					if self._command_queue[0].isBlocking():
						self._command_queue_process = False
						if done == False:
							logger.debug("Entering blocking mode")
						else:
							logger.debug("Spawning blocking command")
							c = self._command_queue.pop(0)
							self.spawnCommand(c)
						break
					else:
						c = self._command_queue.pop(0)
						self.spawnCommand(c)
						done = False
			else:
				logger.debug("Waiting for non blocking process to terminate: %d" % threading.activeCount())

			if self._monitor.enabled:
				 # Do actual collect only when timeinterval reached:
				self._monitor.collect()
				# Automated deletion if certains criterias are met,
				# check Monitoring() for details:
				self._monitor.deleteOutdatedHistory()

		return self._quit

	def processCommand(self, p):
		"""
		Process Packet with type COMMAND.
		The request is ignored in case of errors with the packed body xml.

		@param p: Instance of Packet
		"""
		assert p.type == COMMAND, "Packet with type COMMAND expected"
		# parse the body looking for commandString and binaryData
		logger.debug("XML: %r" % p.body)
		if p.body.startswith('?'): p.body = p.body[1:]
		try:
			xml = et.fromstring(p.body)
		except et.ParseError, pe:
			logger.critical("Malformed xml: %s" % pe)
			self._threads[p.guid] = ReplyResponseObserver(
				Packet.newWithRESPONSE(p.guid, "Error")
			)
			self.send(Packet.newWithAUTHRESPONSE(p.guid))
			return
		if xml.tag != "command":
			logger.critical("Malformed command xml received: expected tag 'command' received '%s'" % xml.tag)
			self._threads[p.guid] = ReplyResponseObserver(
				Packet.newWithRESPONSE(p.guid, "Error")
			)
			self.send(Packet.newWithAUTHRESPONSE(p.guid))
			return
		cs = list(xml.findall("commandString"))
		if len(cs) != 1:
			logger.critical("Malformed command xml received: expected 1 tag 'commandString' received %d tags" % len(cs))
			self._threads[p.guid] = ReplyResponseObserver(
				Packet.newWithRESPONSE(p.guid, "Error")
			)
			self.send(Packet.newWithAUTHRESPONSE(p.guid))
			return
		cmd = cs[0].text
		bd = list(xml.findall("binaryData"))

		if len(bd) == 1:
			try:
				bd = base64.b64decode(bd[0].text)
			except TypeError, te:
				logger.critical("Malformed base64encoded binary data: %s" % te)
				self._threads[p.guid] = ReplyResponseObserver(
					Packet.newWithRESPONSE(p.guid, "Error")
				)
				self.send(Packet.newWithAUTHRESPONSE(p.guid))
				return
			# Save binary data in a temporary file and store its path
			tf = os.path.join(tempfile.gettempdir(), p.guid)
			open(tf, "wb").write(bd)
			bd = tf
		else:
			bd = ""

		# We answer that we have received it
		p = Packet.newWithRECEIVED(p.guid)
		self.send(p)

		# Add the new request in a queue processed by the main loop
		c = Command(
			command=cmd,
			guid=p.guid,
			binary_data=bd,
			monitor=self._monitor
		)
		self._command_queue.append(c)

	def processAuthResponse(self, p):
		"""
		Process Packet with type AUTHRESPONSE.

		@param p: Instance of Packet
		"""
		assert p.type == AUTHRESPONSE, "Packet with type AUTHRESPONSE expected"
		try:
			co = self._threads[p.guid]
			reply = co.responsePacket()
			self.send(reply)
			del self._threads[p.guid]
		except KeyError:
			logger.error("Response requested for an unknow packet id: %s" % p.guid)
			reply = Packet.newWithRESPONSE(p.guid, "Error")
			self.send(reply)

	def processPacket(self, p):
		"""
		Parse and process Packet p

		@param p: Instance of Packet
		"""
		if p.type == ACK:
			logger.info("[%s] ACK Received" % p.guid)
			p = Packet.newWithACK(p.guid)
			self.send(p)
		if p.type == COMMAND:
			if N_DEBUG_FAKE_REQUESTS:
				cl = None
				# For debugging purpose, simulate received requests:
				xml = et.fromstring(p.body)
				cl = xml.find('commandString').text
				if cl == 'systemstatus' and os.path.exists('/hist'):
					p = Packet(
						p.guid,
						p.type,
						p.body.replace('systemstatus', 'systemstatus history'),
						number=1,
						count=1)
					logger.debug('Forged a fake history packet')
				elif cl == 'systemstatus' and os.path.exists('/mstart'):
					p = Packet(
						p.guid,
						p.type,
						p.body.replace('systemstatus', 'systemstatus monitorstart'),
						number=1,
						count=1)
					logger.debug('Forged a fake monitorstart packet')
				elif cl == 'systemstatus' and os.path.exists('/mstop'):
					p = Packet(
						p.guid,
						p.type,
						p.body.replace('systemstatus', 'systemstatus monitorstop'),
						number=1,
						count=1)
					logger.debug('Forged a fake monitorstop packet')
				elif cl == 'systemstatus' and os.path.exists('/rtime'):
					p = Packet(
						p.guid,
						p.type,
						p.body.replace('systemstatus', 'systemstatus retentiontime 2'),
						number=1,
						count=1)
					logger.debug('Forged a fake retentiontime 1 packet')
				elif cl == 'systemstatus' and os.path.exists('/delhist'):
					p = Packet(
						p.guid,
						p.type,
						p.body.replace('systemstatus', 'systemstatus deletehistory'),
						number=1,
						count=1)
					logger.debug('Forged a fake deletehistory packet')
				elif cl == 'systemstatus' and os.path.exists('/monitconf'):
					p = Packet(
						p.guid,
						p.type,
						p.body.replace('systemstatus', 'systemstatus monitorconf'),
						number=1,
						count=1)
					logger.debug('Forged a fake monitorconf packet')
			logger.info("[%s] COMMAND Received" % p.guid)
			self.processCommand(p)
		if p.type == RECEIVED:
			pass
		if p.type == AUTHRESPONSE:
			logger.info("[%s] AUTHRESPONSE Received for request" % p.guid)
			self.processAuthResponse(p)
		if p.type == RESPONSE:
			logger.error("[%s] RESPONSE Received for request" % p.guid)

	def spawnCommand(self, cmd):
		"""
		Spawn the command and register it for later query
		"""
		assert isinstance(cmd, Command), "Expected an instance of type command"
		if cmd.command == 'restart' or cmd.command.startswith('updateSoftware'):
			saveRestartGUID(cmd.guid)
		timeout = self._args['TIMEOUT'].get(
			cmd.moduleName(),
			self._command_timeout
		)
		try:
			timeout = int(timeout)
		except ValueError:
			timeout = self._command_timeout
		co = cmd.spawn(timeout, self)
		self._threads[cmd.guid] = co
		co.start()

	def simulate(self, command, binary_data):
		"""
		Enter simulation mode: basically it sends a small amount of command
		packets waiting and validating the answer sent back from another
		instance of service.

		Used for development and debugging only.
		"""
		logger.debug("Simulating requests")
		if binary_data != None:
			bd = open(binary_data).read()
		else:
			bd = None

		if 0:
			self.send(Packet.newWithACK(guidFromInt(0)))
			r = self.read()
			assert r.type == ACK

		test = [guidFromInt(k+1) for k in range(N_DEBUG_REQUEST)]
		for k in test:
			self.send(Packet.newWithCOMMAND(k, command, bd))

		while len(test) != 0:
			r = self.read()
			if r.type == RECEIVED:
				pass
			if r.type == AUTHRESPONSE:
				self.send(Packet.newWithAUTHRESPONSE(r.guid))
			if r.type == RESPONSE:
				assert r.guid in test, "Request already cleaned"
				test.remove(r.guid)

def parseArgs(command_line, silent=False):
	"""
	Return a tuple with:
		configuration dictionary generated by parsing passed arguments using
		ArgumentParser
		ArgumentParser.Namespace
	"""
	parser = argparse.ArgumentParser(
		description='Execute commands received through the serial port',
		fromfile_prefix_chars='@'
	)

	if silent:
		# by default orgparse will exit if one argument is not valid, we don't
		# want that when we run as a windows service (we trap it properly)
		def myerror(self, message):
			self.error_triggered = True
			self.print_usage(_sys.stderr)
		parser.error = myerror

	conf_from_ini = getConfigurationFromINI()

	# serial port arguments
	parser.add_argument(
		'--port',
		help='serial port (default: open first serial port)',
		dest='serial_port',
		default=conf_from_ini['SERIAL']['port']
	)

	parser.add_argument(
		'--baudrate',
		help='serial port baudrate (default: %(default)s)',
		dest='baudrate',
		type=int,
		default=conf_from_ini['SERIAL']['baudrate']
	)

	parser.add_argument(
		'--bytesize',
		help='serial port bytesize (default: %(default)s)',
		dest='bytesize',
		choices=[
			serial.FIVEBITS,
			serial.SIXBITS,
			serial.SEVENBITS,
			serial.EIGHTBITS
		],
		default=conf_from_ini['SERIAL']['bytesize']
	)

	parser.add_argument(
		'--parity',
		help='serial port parity (default: %(default)s)',
		dest='parity',
		choices=[
			serial.PARITY_NONE,
			serial.PARITY_EVEN,
			serial.PARITY_ODD,
			serial.PARITY_MARK,
			serial.PARITY_SPACE
		],
		default=conf_from_ini['SERIAL']['parity']
	)

	parser.add_argument(
		'--stopbits',
		help='serial port stopbits (default: %(default)s)',
		dest='stopbits',
		choices=[
			serial.STOPBITS_ONE,
			serial.STOPBITS_ONE_POINT_FIVE,
			serial.STOPBITS_TWO
		],
		default=conf_from_ini['SERIAL']['stopbits']
	)

	# extra
	parser.add_argument(
		'--exec',
		help='exec any python script using the current interpreter',
		dest='exec_script',
		default=None
	)

	parser.add_argument(
		'--command-timeout',
		help='debug: command execution timeout in seconds(default: %(default)s sec)',
		dest='command_timeout',
		type=int,
		default=conf_from_ini['PLUGINS']['command_timeout']
	)

	parser.add_argument(
		'--debug-command',
		help='debug: send a command packet',
		dest='debug_command',
		default=None
	)

	parser.add_argument(
		'--debug-command-binary-data',
		help='debug: add binary data to the command packet',
		dest='debug_command_bd',
		default=None
	)

	parser.add_argument(
		'--send-raw',
		help='send raw packet',
		dest='send_raw',
		default=None
	)

	parser.add_argument(
		'--log',
		help='enable logging to file (default: %(default)s)',
		dest='log',
		default=conf_from_ini['LOG']['file']
	)

	parser.add_argument(
		'--log-level',
		help='log level (default: %(default)s)',
		dest='log_level',
		default=conf_from_ini['LOG']['level']
	)

	parser.add_argument(
		'--log-syslog',
		help='enable logging to syslog server',
		dest='syslog_address',
		default=conf_from_ini['LOG']['syslog_address']
	)

	parser.add_argument(
		'--pid',
		help='PID file path',
		dest='pid',
		metavar='PATH'
	)

	parser.add_argument(
		'--daemon',
		help='daemonize',
		dest='daemon',
		action='store_true'
	)

	args = parser.parse_args(command_line)
	if getattr(parser, 'error_triggered', False):
		return None

	return (getConfigurationDictFromArgparse(args), args)

def shellRun(config, args):
	"""
	Run the service as a shell script, no daemon, no service
	"""
	global logger
	logger = configureLogging(config)

	# start the service
	s = Service(config)
	try:
		s.start()

		if args.daemon:
			daemonize(args.pid)
		elif args.pid:
			pidfile = file(args.pid, 'w')
			pidfile.write(str(os.getpid()))
			pidfile.close()
	except serial.serialutil.SerialException, msg:
		logging.critical(str(msg))
		return 1

	if args.send_raw != None:
		e = eval("'" + args.send_raw + "'")
		print 'Sending:', repr(e)
		s.sp.write(e)
		p = s.read()
		print repr(p)
		return 0

	if args.debug_command == None:
		s.run()
	else:
		s.simulate(args.debug_command, args.debug_command_bd)

	return 0

def isInternalCommand(command):
	"""
	Check if provided 'command' matches (starts like) an internal command,
	as defined by global constant: INTERNAL_COMMANDS

	@param command: String representing a command line
	"""
	# Exit on first match. The task of finding against which internal command
	# the match is found is either to be done on caller side, or in a more
	# specialized function.
	for icom in INTERNAL_COMMANDS:
		if command.startswith(icom):
			return True
	return False

if __name__ == "__main__":
	# if we get passed --exec it means we just play the role of a python interpreter
	if len(sys.argv) > 2 and "--exec" == sys.argv[1]:
		sys.path = ['.'] + sys.path
		module = sys.argv[2]
		sys.argv = sys.argv[2:]
		execfile(module, globals())
	else:
		_config, _args = parseArgs(sys.argv[1:])
		sys.exit(shellRun(_config, _args))

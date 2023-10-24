# -*- coding: utf-8 -*-
"""Parser for M365 Defender Advanced hunting files."""

import pyparsing
import csv
import io
import json

from dfdatetime import time_elements as dfdatetime_time_elements
from dfvfs.helpers import text_file

from plaso.containers import events
from plaso.lib import definitions
from plaso.lib import errors
from plaso.parsers import interface
from plaso.parsers import manager
from plaso.parsers import logger

class DefenderAdvancedHuntingScanCompletedEventData(events.EventData):
	"""Parser for M365 Defender Advanced hunting event data.
	
	Action type = AntivirusScanCompleted

	Attributes:
		timestamp (dfdatetime): timestamp of event 
		deviceid (str): device id
		devicename (str): device name
		additionalfields (str): additional fileds
	"""

	DATA_TYPE = 'defender:advanced_hunting:scancomplete'

	def __init__(self):
		"""Initializes event data."""
		super(DefenderAdvancedHuntingScanCompletedEventData, self).__init__(data_type=self.DATA_TYPE)
		self.timestamp = None
		self.deviceid = None
		self.devicename = None
		self.additionalfields = None

class DefenderAdvancedHuntingAsrTheftAuditedEventData(events.EventData):
	"""Parser for M365 Defender Advanced hunting event data.

	Action type = AsrLsassCredentialTheftAudited

	Attributes:
		timestamp (dfdatetime): timestamp of event
		deviceid (str): device id
		devicename (str): device name
		filename (str): file name of process
		folderpath (str): folder path of process
		sha256 (str): sha256 of process file
		processcommandline (str): command-line for process
		initiatingprocessaccountdomain (str): identity domain for initiating process
		initiatingprocessaccountname (str): identity name for initiating process
		initiatingprocesssha256 (str): sha256 of initiating process file
		initiatingprocessfilename (str): file name of initiating process
		initiatingprocessid (str): initiating process id (ppid)
		initiatingprocesscommandline (str): command-line for initiating process
		initiatingprocesscreationtime (str): date and time for initiating process creation
		initiatingprocessfolderpath (str): folder path of initiating process
		initiatingprocessparentid (str): parent process id (pppid)
		initiatingprocessparentfilename (str): file name of parent process
		initiatingprocessparentcreationtime (str): date and time for parent process creation
		additionalfields (str): additional fileds
	"""

	DATA_TYPE = 'defender:advanced_hunting:asrtheftaudited'

	def __init__(self):
		"""Initializes event data."""
		super(DefenderAdvancedHuntingAsrTheftAuditedEventData, self).__init__(data_type=self.DATA_TYPE)
		self.timestamp = None
		self.deviceid = None
		self.devicename = None
		self.filename = None
		self.folderpath = None
		self.sha256 = None
		self.processcommandline = None
		self.initiatingprocessaccountdomain = None
		self.initiatingprocessaccountname = None
		self.initiatingprocesssha256 = None
		self.initiatingprocessfilename = None
		self.initiatingprocessid = None
		self.initiatingprocesscommandline = None
		self.initiatingprocesscreationtime = None
		self.initiatingprocessfolderpath = None
		self.initiatingprocessparentid = None
		self.initiatingprocessparentfilename = None
		self.initiatingprocessparentcreationtime = None
		self.additionalfields = None

class DefenderAdvancedHuntingConnFailedEventData(events.EventData):
	"""Parser for M365 Defender Advanced hunting event data.

	Action type = ConnectionFailed

	Attributes:
		timestamp (dfdatetime): timestamp of event
		deviceid (str): device id
		devicename (str): device name
		initiatingprocessaccountdomain (str): identity domain for initiating process
		initiatingprocessaccountname (str): identity name for initiating process
		initiatingprocesssha256 (str): sha256 of initiating process file
		initiatingprocessfilename (str): file name of initiating process
		initiatingprocessid (str): initiating process id (ppid)
		initiatingprocesscommandline (str): command-line for initiating process
		initiatingprocesscreationtime (str): date and time for initiating process creation
		initiatingprocessfolderpath (str): folder path of initiating process
		initiatingprocessparentid (str): parent process id (pppid)
		initiatingprocessparentfilename (str): file name of parent process
		initiatingprocessparentcreationtime (str): date and time for parent process creation
		remoteip (str): remote ip address
		remoteport (str): remote port
		remoteurl (str): remote url address
		localip (str): local ip address
		localport (str): local port
		protocol (str): used protocol
	"""

	DATA_TYPE = 'defender:advanced_hunting:connfailed'

	def __init__(self):
		"""Initializes event data."""
		super(DefenderAdvancedHuntingConnFailedEventData, self).__init__(data_type=self.DATA_TYPE)
		self.timestamp = None
		self.deviceid = None
		self.devicename = None
		self.initiatingprocessaccountdomain = None
		self.initiatingprocessaccountname = None
		self.initiatingprocesssha256 = None
		self.initiatingprocessfilename = None
		self.initiatingprocessid = None
		self.initiatingprocesscommandline = None
		self.initiatingprocesscreationtime = None
		self.initiatingprocessfolderpath = None
		self.initiatingprocessparentid = None
		self.initiatingprocessparentfilename = None
		self.initiatingprocessparentcreationtime = None
		self.remoteip = None
		self.remoteport = None
		self.remoteurl = None
		self.localip = None
		self.localport = None
		self.protocol = None

class DefenderAdvancedHuntingConnSuccessEventData(events.EventData):
	"""Parser for M365 Defender Advanced hunting event data.

	Action type = ConnectionSuccess

	Attributes:
		timestamp (dfdatetime): timestamp of event
		deviceid (str): device id
		devicename (str): device name
		initiatingprocessaccountdomain (str): identity domain for initiating process
		initiatingprocessaccountname (str): identity name for initiating process
		initiatingprocesssha256 (str): sha256 of initiating process file
		initiatingprocessfilename (str): file name of initiating process
		initiatingprocessid (str): initiating process id (ppid)
		initiatingprocesscommandline (str): command-line for initiating process
		initiatingprocesscreationtime (str): date and time for initiating process creation
		initiatingprocessfolderpath (str): folder path of initiating process
		initiatingprocessparentid (str): parent process id (pppid)
		initiatingprocessparentfilename (str): file name of parent process
		initiatingprocessparentcreationtime (str): date and time for parent process creation
		remoteip (str): remote ip address
		remoteport (str): remote port
		remoteurl (str): remote url address
		localip (str): local ip address
		localport (str): local port
		protocol (str): used protocol
	"""

	DATA_TYPE = 'defender:advanced_hunting:connsuccess'

	def __init__(self):
		"""Initializes event data."""
		super(DefenderAdvancedHuntingConnSuccessEventData, self).__init__(data_type=self.DATA_TYPE)
		self.timestamp = None
		self.deviceid = None
		self.devicename = None
		self.initiatingprocessaccountdomain = None
		self.initiatingprocessaccountname = None
		self.initiatingprocesssha256 = None
		self.initiatingprocessfilename = None
		self.initiatingprocessid = None
		self.initiatingprocesscommandline = None
		self.initiatingprocesscreationtime = None
		self.initiatingprocessfolderpath = None
		self.initiatingprocessparentid = None
		self.initiatingprocessparentfilename = None
		self.initiatingprocessparentcreationtime = None
		self.remoteip = None
		self.remoteport = None
		self.remoteurl = None
		self.localip = None
		self.localport = None
		self.protocol = None

class DefenderAdvancedHuntingDnsInspectedEventData(events.EventData):
	"""Parser for M365 Defender Advanced hunting event data.

	Action type = DnsConnectionInspected

	Attributes:
		timestamp (dfdatetime): timestamp of event
		deviceid (str): device id
		devicename (str): device name
		remoteip (str): remote ip address
		remoteport (str): remote port
		localip (str): local ip address
		localport (str): local port
		protocol (str): used protocol
		dnsquery (str): dns query
		additionalfields (str): additional fileds
	"""

	DATA_TYPE = 'defender:advanced_hunting:dnsinspected'

	def __init__(self):
		"""Initializes event data."""
		super(DefenderAdvancedHuntingDnsInspectedEventData, self).__init__(data_type=self.DATA_TYPE)
		self.timestamp = None
		self.deviceid = None
		self.devicename = None
		self.remoteip = None
		self.remoteport = None
		self.localip = None
		self.localport = None
		self.protocol = None
		self.dnsquery = None
		self.additionalfields = None

class DefenderAdvancedHuntingIcmpInspectedEventData(events.EventData):
	"""Parser for M365 Defender Advanced hunting event data.

	Action type = IcmpConnectionInspected

	Attributes:
		timestamp (dfdatetime): timestamp of event
		deviceid (str): device id
		devicename (str): device name
		remoteip (str): remote ip address
		localip (str): local ip address
		protocol (str): used protocol
		additionalfields (str): additional fileds
	"""

	DATA_TYPE = 'defender:advanced_hunting:icmpinspected'

	def __init__(self):
		"""Initializes event data."""
		super(DefenderAdvancedHuntingIcmpInspectedEventData, self).__init__(data_type=self.DATA_TYPE)
		self.timestamp = None
		self.deviceid = None
		self.devicename = None
		self.remoteip = None
		self.localip = None
		self.protocol = None
		self.additionalfields = None

class DefenderAdvancedHuntingInConnectionAcceptedEventData(events.EventData):
	"""Parser for M365 Defender Advanced hunting event data.

	Action type = InboundConnectionAccepted

	Attributes:
		timestamp (dfdatetime): timestamp of event
		deviceid (str): device id
		devicename (str): device name
		initiatingprocessaccountdomain (str): identity domain for initiating process
		initiatingprocessaccountname (str): identity name for initiating process
		initiatingprocesssha256 (str): sha256 of initiating process file
		initiatingprocessfilename (str): file name of initiating process
		initiatingprocessid (str): initiating process id (ppid)
		initiatingprocesscommandline (str): command-line for initiating process
		initiatingprocesscreationtime (str): date and time for initiating process creation
		initiatingprocessfolderpath (str): folder path of initiating process
		initiatingprocessparentid (str): parent process id (pppid)
		initiatingprocessparentfilename (str): file name of parent process
		initiatingprocessparentcreationtime (str): date and time for parent process creation
		remoteip (str): remote ip address
		remoteport (str): remote port
		localip (str): local ip address
		localport (str): local port
		protocol (str): used protocol
	"""

	DATA_TYPE = 'defender:advanced_hunting:inconnaccept'

	def __init__(self):
		"""Initializes event data."""
		super(DefenderAdvancedHuntingInConnectionAcceptedEventData, self).__init__(data_type=self.DATA_TYPE)
		self.timestamp = None
		self.deviceid = None
		self.devicename = None
		self.initiatingprocessaccountdomain = None
		self.initiatingprocessaccountname = None
		self.initiatingprocesssha256 = None
		self.initiatingprocessfilename = None
		self.initiatingprocessid = None
		self.initiatingprocesscommandline = None
		self.initiatingprocesscreationtime = None
		self.initiatingprocessfolderpath = None
		self.initiatingprocessparentid = None
		self.initiatingprocessparentfilename = None
		self.initiatingprocessparentcreationtime = None
		self.remoteip = None
		self.remoteport = None
		self.localip = None
		self.localport = None
		self.protocol = None

class DefenderAdvancedHuntingListeningConnectionCreatedEventData(events.EventData):
	"""Parser for M365 Defender Advanced hunting event data.

	Action type = ListeningConnectionCreated

	Attributes:
		timestamp (dfdatetime): timestamp of event
		deviceid (str): device id
		devicename (str): device name
		initiatingprocessaccountdomain (str): identity domain for initiating process
		initiatingprocessaccountname (str): identity name for initiating process
		initiatingprocesssha256 (str): sha256 of initiating process file
		initiatingprocessfilename (str): file name of initiating process
		initiatingprocessid (str): initiating process id (ppid)
		initiatingprocesscommandline (str): command-line for initiating process
		initiatingprocesscreationtime (str): date and time for initiating process creation
		initiatingprocessfolderpath (str): folder path of initiating process
		initiatingprocessparentid (str): parent process id (pppid)
		initiatingprocessparentfilename (str): file name of parent process
		initiatingprocessparentcreationtime (str): date and time for parent process creation
		localip (str): local ip address
		localport (str): local port
		protocol (str): used protocol
	"""

	DATA_TYPE = 'defender:advanced_hunting:listenconncreated'

	def __init__(self):
		"""Initializes event data."""
		super(DefenderAdvancedHuntingListeningConnectionCreatedEventData, self).__init__(data_type=self.DATA_TYPE)
		self.timestamp = None
		self.deviceid = None
		self.devicename = None
		self.initiatingprocessaccountdomain = None
		self.initiatingprocessaccountname = None
		self.initiatingprocesssha256 = None
		self.initiatingprocessfilename = None
		self.initiatingprocessid = None
		self.initiatingprocesscommandline = None
		self.initiatingprocesscreationtime = None
		self.initiatingprocessfolderpath = None
		self.initiatingprocessparentid = None
		self.initiatingprocessparentfilename = None
		self.initiatingprocessparentcreationtime = None
		self.localip = None
		self.localport = None
		self.protocol = None

class DefenderAdvancedHuntingPowerShellCommandEventData(events.EventData):
	"""Parser for M365 Defender Advanced hunting event data.

	Action type = PowerShellCommand

	Attributes:
		timestamp (dfdatetime): timestamp of event
		deviceid (str): device id
		devicename (str): device name
		initiatingprocessaccountdomain (str): identity domain for initiating process
		initiatingprocessaccountname (str): identity name for initiating process
		initiatingprocesssha256 (str): sha256 of initiating process file
		initiatingprocessfilename (str): file name of initiating process
		initiatingprocessid (str): initiating process id (ppid)
		initiatingprocesscommandline (str): command-line for initiating process
		initiatingprocesscreationtime (str): date and time for initiating process creation
		initiatingprocessfolderpath (str): folder path of initiating process
		initiatingprocessparentid (str): parent process id (pppid)
		initiatingprocessparentfilename (str): file name of parent process
		initiatingprocessparentcreationtime (str): date and time for parent process creation
		powershellcommand (str): powershell command
	"""

	DATA_TYPE = 'defender:advanced_hunting:powershellcommand'

	def __init__(self):
		"""Initializes event data."""
		super(DefenderAdvancedHuntingPowerShellCommandEventData, self).__init__(data_type=self.DATA_TYPE)
		self.timestamp = None
		self.deviceid = None
		self.devicename = None
		self.initiatingprocessaccountdomain = None
		self.initiatingprocessaccountname = None
		self.initiatingprocesssha256 = None
		self.initiatingprocessfilename = None
		self.initiatingprocessid = None
		self.initiatingprocesscommandline = None
		self.initiatingprocesscreationtime = None
		self.initiatingprocessfolderpath = None
		self.initiatingprocessparentid = None
		self.initiatingprocessparentfilename = None
		self.initiatingprocessparentcreationtime = None
		self.powershellcommand = None

class DefenderAdvancedHuntingProcessCreatedEventData(events.EventData):
	"""Parser for M365 Defender Advanced hunting event data.

	Action type = ProcessCreated

	Attributes:
		timestamp (dfdatetime): timestamp of event
		deviceid (str): device id
		devicename (str): device name
		actiontype (str): type of event
		filename (str): file name of process
		folderpath (str): folder path of process
		sha256 (str): sha256 of process file
		processid (str): process id (pid)
		processcommandline (str): command-line for process
		processcreationtime (str): date and time for process creation
		accountdomain (str): identity domain for process
		accountname (str): identity name for process
		initiatingprocessaccountdomain (str): identity domain for initiating process
		initiatingprocessaccountname (str): identity name for initiating process
		initiatingprocesssha256 (str): sha256 of initiating process file
		initiatingprocessfilename (str): file name of initiating process
		initiatingprocessid (str): initiating process id (ppid)
		initiatingprocesscommandline (str): command-line for initiating process
		initiatingprocesscreationtime (str): date and time for initiating process creation
		initiatingprocessfolderpath (str): folder path of initiating process
		initiatingprocessparentid (str): parent process id (pppid)
		initiatingprocessparentfilename (str): file name of parent process
		initiatingprocessparentcreationtime (str): date and time for parent process creation
	"""

	DATA_TYPE = 'defender:advanced_hunting:processcreated'

	def __init__(self):
		"""Initializes event data."""
		super(DefenderAdvancedHuntingProcessCreatedEventData, self).__init__(data_type=self.DATA_TYPE)
		self.timestamp = None
		self.deviceid = None
		self.devicename = None
		self.actiontype = None
		self.filename = None
		self.folderpath = None
		self.sha256 = None
		self.processid = None
		self.processcommandline = None
		self.processcreationtime = None
		self.accountdomain = None
		self.accountname = None
		self.initiatingprocessaccountdomain = None
		self.initiatingprocessaccountname = None
		self.initiatingprocesssha256 = None
		self.initiatingprocessfilename = None
		self.initiatingprocessid = None
		self.initiatingprocesscommandline = None
		self.initiatingprocesscreationtime = None
		self.initiatingprocessfolderpath = None
		self.initiatingprocessparentid = None
		self.initiatingprocessparentfilename = None
		self.initiatingprocessparentcreationtime = None

class DefenderAdvancedHuntingProcessCreatedUsingWmiQueryEventData(events.EventData):
	"""Parser for M365 Defender Advanced hunting event data.

	Action type = ProcessCreatedUsingWmiQuery

	Attributes:
		timestamp (dfdatetime): timestamp of event
		deviceid (str): device id
		devicename (str): device name
		initiatingprocessaccountdomain (str): identity domain for initiating process
		initiatingprocessaccountname (str): identity name for initiating process
		additionalfields (str): additional fileds
	"""

	DATA_TYPE = 'defender:advanced_hunting:processcreatedwmi'

	def __init__(self):
		"""Initializes event data."""
		super(DefenderAdvancedHuntingProcessCreatedUsingWmiQueryEventData, self).__init__(data_type=self.DATA_TYPE)
		self.timestamp = None
		self.deviceid = None
		self.devicename = None
		self.initiatingprocessaccountdomain = None
		self.initiatingprocessaccountname = None
		self.additionalfields = None

class DefenderAdvancedHuntingServiceInstalledEventData(events.EventData):
	"""Parser for M365 Defender Advanced hunting event data.

	Action type = ServiceInstalled

	Attributes:
		timestamp (dfdatetime): timestamp of event
		deviceid (str): device id
		devicename (str): device name
		filename (str): file name of process
		folderpath (str): folder path of process
		initiatingprocessaccountdomain (str): identity domain for initiating process
		initiatingprocessaccountname (str): identity name for initiating process
		initiatingprocesssha256 (str): sha256 of initiating process file
		initiatingprocessfilename (str): file name of initiating process
		initiatingprocessid (str): initiating process id (ppid)
		initiatingprocesscommandline (str): command-line for initiating process
		initiatingprocesscreationtime (str): date and time for initiating process creation
		initiatingprocessfolderpath (str): folder path of initiating process
		initiatingprocessparentid (str): parent process id (pppid)
		initiatingprocessparentfilename (str): file name of parent process
		initiatingprocessparentcreationtime (str): date and time for parent process creation
		additionalfields (str): additional fileds
	"""

	DATA_TYPE = 'defender:advanced_hunting:serviceinstalled'

	def __init__(self):
		"""Initializes event data."""
		super(DefenderAdvancedHuntingServiceInstalledEventData, self).__init__(data_type=self.DATA_TYPE)
		self.timestamp = None
		self.deviceid = None
		self.devicename = None
		self.filename = None
		self.folderpath = None
		self.initiatingprocessaccountdomain = None
		self.initiatingprocessaccountname = None
		self.initiatingprocesssha256 = None
		self.initiatingprocessfilename = None
		self.initiatingprocessid = None
		self.initiatingprocesscommandline = None
		self.initiatingprocesscreationtime = None
		self.initiatingprocessfolderpath = None
		self.initiatingprocessparentid = None
		self.initiatingprocessparentfilename = None
		self.initiatingprocessparentcreationtime = None
		self.additionalfields = None

class DefenderAdvancedHuntingParser(interface.FileObjectParser):
	"""Parser for M365 Defender Advanced hunting files."""

	NAME = 'defender_hunting'
	DATA_FORMAT = 'M365 Defender Advanced hunting export'

	ENCODING = 'utf-8'

	_testing = 0

	_TWO_DIGITS = pyparsing.Word(pyparsing.nums, exact=2).setParseAction(
		lambda tokens: int(tokens[0], 10))

	_FOUR_DIGITS = pyparsing.Word(pyparsing.nums, exact=4).setParseAction(
		lambda tokens: int(tokens[0], 10))

	_MILISEC_DIGITS = pyparsing.Word(pyparsing.nums, max=7).setParseAction(
		lambda tokens: int(tokens[0], 10))

	# 2023-10-18T15:45:07.9862755Z
	_TIMESTAMP = pyparsing.Group(
		_FOUR_DIGITS + pyparsing.Suppress('-') +
		_TWO_DIGITS + pyparsing.Suppress('-') +
		_TWO_DIGITS + pyparsing.Suppress('T') +
		_TWO_DIGITS + pyparsing.Suppress(':') +
		_TWO_DIGITS + pyparsing.Suppress(':') +
		_TWO_DIGITS + pyparsing.Suppress('.') +
		_MILISEC_DIGITS + pyparsing.Suppress('Z')).setResultsName('timestamp')

	_DEVICE_ID = pyparsing.Word(pyparsing.alphanums).setResultsName('device_id')

	_DEVICE_NAME = pyparsing.Word(pyparsing.printables, excludeChars=",").setResultsName('device_name')

	_ACTION_TYPE = pyparsing.Word(pyparsing.alphanums).setResultsName('action_type')

	_END_OF_LINE = pyparsing.Suppress(pyparsing.LineEnd())

	_HEADER_LINE = (pyparsing.Literal('Timestamp,DeviceId,DeviceName,ActionType,FileName,FolderPath,SHA1,SHA256,MD5,FileSize,ProcessVersionInfoCompanyName,ProcessVersionInfoProductName,ProcessVersionInfoProductVersion,ProcessVersionInfoInternalFileName,ProcessVersionInfoOriginalFileName,ProcessVersionInfoFileDescription,ProcessId,ProcessCommandLine,ProcessIntegrityLevel,ProcessTokenElevation,ProcessCreationTime,AccountDomain,AccountName,AccountSid,AccountUpn,AccountObjectId,LogonId,InitiatingProcessAccountDomain,InitiatingProcessAccountName,InitiatingProcessAccountSid,InitiatingProcessAccountUpn,InitiatingProcessAccountObjectId,InitiatingProcessLogonId,InitiatingProcessIntegrityLevel,InitiatingProcessTokenElevation,InitiatingProcessSHA1,InitiatingProcessSHA256,InitiatingProcessMD5,InitiatingProcessFileName,InitiatingProcessFileSize,InitiatingProcessVersionInfoCompanyName,InitiatingProcessVersionInfoProductName,InitiatingProcessVersionInfoProductVersion,InitiatingProcessVersionInfoInternalFileName,InitiatingProcessVersionInfoOriginalFileName,InitiatingProcessVersionInfoFileDescription,InitiatingProcessId,InitiatingProcessCommandLine,InitiatingProcessCreationTime,InitiatingProcessFolderPath,InitiatingProcessParentId,InitiatingProcessParentFileName,InitiatingProcessParentCreationTime,InitiatingProcessSignerType,InitiatingProcessSignatureStatus,ReportId,AppGuardContainerId,AdditionalFields,RemoteIP,RemotePort,RemoteUrl,LocalIP,LocalPort,Protocol,LocalIPType,RemoteIPType,RemoteDeviceName,RegistryKey,RegistryValueName,RegistryValueData,FileOriginUrl,FileOriginIP') + _END_OF_LINE)

	_DATA_LINE = (_TIMESTAMP + pyparsing.Suppress(',') + _DEVICE_ID + pyparsing.Suppress(',') + _DEVICE_NAME + pyparsing.Suppress(',') + _ACTION_TYPE + pyparsing.Suppress(',') + pyparsing.restOfLine().setResultsName('optional_data') + _END_OF_LINE)
	
	def _ParseTimeElements(self, time_elements_structure):
		"""Parses date and time elements of a log line.

		Args:
			time_elements_structure (pyparsing.ParseResults): date and time elements of a log line.

		Returns:
			dfdatetime.TimeElements: date and time value.

		Raises:
			ParseError: if a valid date and time value cannot be derived from the time elements.
		"""

		if self._testing != 0 :
			logger.info('request for parse time ...')
			logger.info('structure: {0!s}'.format(
				time_elements_structure))

		try:
			year, month, day_of_month, hours, minutes, seconds, miliseconds = (
				time_elements_structure)

			# Ensure time_elements_tuple is not a pyparsing.ParseResults otherwise
			# copy.deepcopy() of the dfDateTime object will fail on Python 3.8 with:
			# "TypeError: 'str' object is not callable" due to pyparsing.ParseResults
			# overriding __getattr__ with a function that returns an empty string
			# when named token does not exist.
			time_elements_tuple = (year, month, day_of_month, hours, minutes, seconds)
			date_time = dfdatetime_time_elements.TimeElements(
				time_elements_tuple=time_elements_tuple)

			return date_time

		except (TypeError, ValueError) as exception:
			raise errors.ParseError(
				'Unable to parse time elements with error: {0!s}'.format(exception))

	def _ParseValues(self, parser_mediator, values):
		"""Parses M365 Defender Advanced hunting values.

		Args:
			values (list[str]): values extracted from the line.

		Raises:
			WrongParser: when the line cannot be parsed.
		"""

		if self._testing != 0 :
			logger.info('request for parse values ...')
			logger.info('action: {0!s}'.format(
				values['ActionType']))

		allowed_actions = [
			'AntivirusScanCompleted',
			'AsrLsassCredentialTheftAudited',
			'ConnectionFailed',
			'ConnectionSuccess',
			'DnsConnectionInspected',
			'IcmpConnectionInspected',
			'InboundConnectionAccepted',
			'ListeningConnectionCreated',
			'PowerShellCommand',
			'ProcessCreated',
			'ProcessCreatedUsingWmiQuery',
			'ServiceInstalled']
		
		if values['ActionType'] not in allowed_actions:
			parser_mediator.ProduceExtractionWarning(
				'Not allowed action: {0!s}'.format(
					values['ActionType']))

		if values['ActionType'] == "AntivirusScanCompleted":
			self._ParseValuesAntivirusScanCompleted(parser_mediator, values)

		if values['ActionType'] == "AsrLsassCredentialTheftAudited":
			self._ParseValuesAsrTheftAudited(parser_mediator, values)
			
		if values['ActionType'] == "ConnectionFailed":
			self._ParseValuesConnFailed(parser_mediator, values)

		if values['ActionType'] == "ConnectionSuccess":
			self._ParseValuesConnSuccess(parser_mediator, values)
			
		if values['ActionType'] == "DnsConnectionInspected":
			self._ParseValuesDnsInspected(parser_mediator, values)
			
		if values['ActionType'] == "IcmpConnectionInspected":
			self._ParseValuesIcmpInspected(parser_mediator, values)

		if values['ActionType'] == "InboundConnectionAccepted":
			self._ParseValuesInConnectionAccepted(parser_mediator, values)
			
		if values['ActionType'] == "ListeningConnectionCreated":
			self._ParseValuesListeningConnectionCreated(parser_mediator, values)
			
		if values['ActionType'] == "PowerShellCommand":
			self._ParseValuesPowerShellCommand(parser_mediator, values)

		if values['ActionType'] == "ProcessCreated":
			self._ParseValuesProcessCreated(parser_mediator, values)
			
		if values['ActionType'] == "ProcessCreatedUsingWmiQuery":
			self._ParseValuesProcessCreatedUsingWmiQuery(parser_mediator, values)

		if values['ActionType'] == "ServiceInstalled":
			self._ParseValuesServiceInstalled(parser_mediator, values)
			
	def _ParseValuesAntivirusScanCompleted(self, parser_mediator, values):
		"""Parses M365 Defender Advanced hunting values.

		Action type = AntivirusScanCompleted

		Args:
			values (list[str]): values extracted from the line.

		"""

		resultTimeParse = self._TIMESTAMP.parseString(values['Timestamp'])        
		time_elements_structure = resultTimeParse['timestamp']

		event_data = DefenderAdvancedHuntingScanCompletedEventData()
		event_data.timestamp = self._ParseTimeElements(time_elements_structure)
		event_data.deviceid = values['DeviceId']
		event_data.devicename = values['DeviceName']
		event_data.additionalfields = values['AdditionalFields']        

		parser_mediator.ProduceEventData(event_data)

	def _ParseValuesAsrTheftAudited(self, parser_mediator, values):
		"""Parses M365 Defender Advanced hunting values.

		Action type = AsrLsassCredentialTheftAudited

		Args:
			values (list[str]): values extracted from the line.

		"""

		resultTimeParse = self._TIMESTAMP.parseString(values['Timestamp'])        
		time_elements_structure = resultTimeParse['timestamp']

		event_data = DefenderAdvancedHuntingAsrTheftAuditedEventData()
		event_data.timestamp = self._ParseTimeElements(time_elements_structure)
		event_data.deviceid = values['DeviceId']
		event_data.devicename = values['DeviceName']
		event_data.filename = values['FileName']
		event_data.folderpath = values['FolderPath']
		event_data.sha256 = values['SHA256']
		event_data.processcommandline = values['ProcessCommandLine']
		event_data.initiatingprocessaccountdomain = values['InitiatingProcessAccountDomain']
		event_data.initiatingprocessaccountname = values['InitiatingProcessAccountName']
		event_data.initiatingprocesssha256 = values['InitiatingProcessSHA256']
		event_data.initiatingprocessfilename = values['InitiatingProcessFileName']
		event_data.initiatingprocessid = values['InitiatingProcessId']
		event_data.initiatingprocesscommandline = values['InitiatingProcessCommandLine']
		event_data.initiatingprocesscreationtime = values['InitiatingProcessCreationTime']
		event_data.initiatingprocessfolderpath = values['InitiatingProcessFolderPath']
		event_data.initiatingprocessparentid = values['InitiatingProcessParentId']
		event_data.initiatingprocessparentfilename = values['InitiatingProcessParentFileName']
		event_data.initiatingprocessparentcreationtime = values['InitiatingProcessParentCreationTime']
		event_data.additionalfields = values['AdditionalFields']        

		parser_mediator.ProduceEventData(event_data)

	def _ParseValuesConnFailed(self, parser_mediator, values):
		"""Parses M365 Defender Advanced hunting values.

		Action type = ConnectionFailed

		Args:
			values (list[str]): values extracted from the line.

		"""
		resultTimeParse = self._TIMESTAMP.parseString(values['Timestamp'])        
		time_elements_structure = resultTimeParse['timestamp']

		event_data = DefenderAdvancedHuntingConnFailedEventData()
		event_data.timestamp = self._ParseTimeElements(time_elements_structure)
		event_data.deviceid = values['DeviceId']
		event_data.devicename = values['DeviceName']
		event_data.initiatingprocessaccountdomain = values['InitiatingProcessAccountDomain']
		event_data.initiatingprocessaccountname = values['InitiatingProcessAccountName']
		event_data.initiatingprocesssha256 = values['InitiatingProcessSHA256']
		event_data.initiatingprocessfilename = values['InitiatingProcessFileName']
		event_data.initiatingprocessid = values['InitiatingProcessId']
		event_data.initiatingprocesscommandline = values['InitiatingProcessCommandLine']
		event_data.initiatingprocesscreationtime = values['InitiatingProcessCreationTime']
		event_data.initiatingprocessfolderpath = values['InitiatingProcessFolderPath']
		event_data.initiatingprocessparentid = values['InitiatingProcessParentId']
		event_data.initiatingprocessparentfilename = values['InitiatingProcessParentFileName']
		event_data.initiatingprocessparentcreationtime = values['InitiatingProcessParentCreationTime']
		event_data.remoteip = values['RemoteIP']
		event_data.remoteport = values['RemotePort']
		event_data.remoteurl = values['RemoteUrl']
		event_data.localip = values['LocalIP']
		event_data.localport = values['LocalPort']
		event_data.protocol = values['Protocol']

		parser_mediator.ProduceEventData(event_data)
	
	def _ParseValuesConnSuccess(self, parser_mediator, values):
		"""Parses M365 Defender Advanced hunting values.

		Action type = ConnectionSuccess

		Args:
			values (list[str]): values extracted from the line.

		"""     
		resultTimeParse = self._TIMESTAMP.parseString(values['Timestamp'])        
		time_elements_structure = resultTimeParse['timestamp']

		event_data = DefenderAdvancedHuntingConnSuccessEventData()
		event_data.timestamp = self._ParseTimeElements(time_elements_structure)
		event_data.deviceid = values['DeviceId']
		event_data.devicename = values['DeviceName']
		event_data.initiatingprocessaccountdomain = values['InitiatingProcessAccountDomain']
		event_data.initiatingprocessaccountname = values['InitiatingProcessAccountName']
		event_data.initiatingprocesssha256 = values['InitiatingProcessSHA256']
		event_data.initiatingprocessfilename = values['InitiatingProcessFileName']
		event_data.initiatingprocessid = values['InitiatingProcessId']
		event_data.initiatingprocesscommandline = values['InitiatingProcessCommandLine']
		event_data.initiatingprocesscreationtime = values['InitiatingProcessCreationTime']
		event_data.initiatingprocessfolderpath = values['InitiatingProcessFolderPath']
		event_data.initiatingprocessparentid = values['InitiatingProcessParentId']
		event_data.initiatingprocessparentfilename = values['InitiatingProcessParentFileName']
		event_data.initiatingprocessparentcreationtime = values['InitiatingProcessParentCreationTime']
		event_data.remoteip = values['RemoteIP']
		event_data.remoteport = values['RemotePort']
		event_data.remoteurl = values['RemoteUrl']
		event_data.localip = values['LocalIP']
		event_data.localport = values['LocalPort']
		event_data.protocol = values['Protocol']

		parser_mediator.ProduceEventData(event_data)

	def  _ParseValuesDnsInspected(self, parser_mediator, values):
		"""Parses M365 Defender Advanced hunting values.

		Action type = DnsConnectionInspected

		Args:
			values (list[str]): values extracted from the line.

		"""     

		resultTimeParse = self._TIMESTAMP.parseString(values['Timestamp'])        
		time_elements_structure = resultTimeParse['timestamp']

		event_data = DefenderAdvancedHuntingDnsInspectedEventData()
		event_data.timestamp = self._ParseTimeElements(time_elements_structure)
		event_data.deviceid = values['DeviceId']
		event_data.devicename = values['DeviceName']
		event_data.remoteip = values['RemoteIP']
		event_data.remoteport = values['RemotePort']
		event_data.localip = values['LocalIP']
		event_data.localport = values['LocalPort']
		event_data.protocol = values['Protocol']
		event_data.additionalfields = values['AdditionalFields']        

		if len(values['AdditionalFields']) > 0 and "query" in values['AdditionalFields']:
			addJson = json.loads(values['AdditionalFields'])
			event_data.dnsquery = addJson['query']
			
		else:
			event_data.dnsquery = ""

		parser_mediator.ProduceEventData(event_data)

	def  _ParseValuesIcmpInspected(self, parser_mediator, values):
		"""Parses M365 Defender Advanced hunting values.

		Action type = IcmpConnectionInspected

		Args:
			values (list[str]): values extracted from the line.

		"""     
		resultTimeParse = self._TIMESTAMP.parseString(values['Timestamp'])        
		time_elements_structure = resultTimeParse['timestamp']

		event_data = DefenderAdvancedHuntingIcmpInspectedEventData()
		event_data.timestamp = self._ParseTimeElements(time_elements_structure)
		event_data.deviceid = values['DeviceId']
		event_data.devicename = values['DeviceName']
		event_data.remoteip = values['RemoteIP']
		event_data.localip = values['LocalIP']
		event_data.protocol = values['Protocol']
		event_data.additionalfields = values['AdditionalFields']        

		parser_mediator.ProduceEventData(event_data)

	def  _ParseValuesInConnectionAccepted(self, parser_mediator, values):
		"""Parses M365 Defender Advanced hunting values.

		Action type = InboundConnectionAccepted

		Args:
			values (list[str]): values extracted from the line.

		"""     
		resultTimeParse = self._TIMESTAMP.parseString(values['Timestamp'])        
		time_elements_structure = resultTimeParse['timestamp']

		event_data = DefenderAdvancedHuntingInConnectionAcceptedEventData()
		event_data.timestamp = self._ParseTimeElements(time_elements_structure)
		event_data.deviceid = values['DeviceId']
		event_data.devicename = values['DeviceName']
		event_data.initiatingprocessaccountdomain = values['InitiatingProcessAccountDomain']
		event_data.initiatingprocessaccountname = values['InitiatingProcessAccountName']
		event_data.initiatingprocesssha256 = values['InitiatingProcessSHA256']
		event_data.initiatingprocessfilename = values['InitiatingProcessFileName']
		event_data.initiatingprocessid = values['InitiatingProcessId']
		event_data.initiatingprocesscommandline = values['InitiatingProcessCommandLine']
		event_data.initiatingprocesscreationtime = values['InitiatingProcessCreationTime']
		event_data.initiatingprocessfolderpath = values['InitiatingProcessFolderPath']
		event_data.initiatingprocessparentid = values['InitiatingProcessParentId']
		event_data.initiatingprocessparentfilename = values['InitiatingProcessParentFileName']
		event_data.initiatingprocessparentcreationtime = values['InitiatingProcessParentCreationTime']
		event_data.remoteip = values['RemoteIP']
		event_data.remoteport = values['RemotePort']
		event_data.localip = values['LocalIP']
		event_data.localport = values['LocalPort']
		event_data.protocol = values['Protocol']

		parser_mediator.ProduceEventData(event_data)

	def _ParseValuesListeningConnectionCreated(self, parser_mediator, values):
		"""Parses M365 Defender Advanced hunting values.

		Action type = ListeningConnectionCreated

		Args:
			values (list[str]): values extracted from the line.

		"""     
		resultTimeParse = self._TIMESTAMP.parseString(values['Timestamp'])        
		time_elements_structure = resultTimeParse['timestamp']

		event_data = DefenderAdvancedHuntingListeningConnectionCreatedEventData()
		event_data.timestamp = self._ParseTimeElements(time_elements_structure)
		event_data.deviceid = values['DeviceId']
		event_data.devicename = values['DeviceName']
		event_data.initiatingprocessaccountdomain = values['InitiatingProcessAccountDomain']
		event_data.initiatingprocessaccountname = values['InitiatingProcessAccountName']
		event_data.initiatingprocesssha256 = values['InitiatingProcessSHA256']
		event_data.initiatingprocessfilename = values['InitiatingProcessFileName']
		event_data.initiatingprocessid = values['InitiatingProcessId']
		event_data.initiatingprocesscommandline = values['InitiatingProcessCommandLine']
		event_data.initiatingprocesscreationtime = values['InitiatingProcessCreationTime']
		event_data.initiatingprocessfolderpath = values['InitiatingProcessFolderPath']
		event_data.initiatingprocessparentid = values['InitiatingProcessParentId']
		event_data.initiatingprocessparentfilename = values['InitiatingProcessParentFileName']
		event_data.initiatingprocessparentcreationtime = values['InitiatingProcessParentCreationTime']
		event_data.localip = values['LocalIP']
		event_data.localport = values['LocalPort']
		event_data.protocol = values['Protocol']

		parser_mediator.ProduceEventData(event_data)

	def _ParseValuesPowerShellCommand(self, parser_mediator, values):
		"""Parses M365 Defender Advanced hunting values.

		Action type = PowerShellCommand

		Args:
			values (list[str]): values extracted from the line.

		"""     
		resultTimeParse = self._TIMESTAMP.parseString(values['Timestamp'])        
		time_elements_structure = resultTimeParse['timestamp']

		event_data = DefenderAdvancedHuntingPowerShellCommandEventData()
		event_data.timestamp = self._ParseTimeElements(time_elements_structure)
		event_data.deviceid = values['DeviceId']
		event_data.devicename = values['DeviceName']
		event_data.initiatingprocessaccountdomain = values['InitiatingProcessAccountDomain']
		event_data.initiatingprocessaccountname = values['InitiatingProcessAccountName']
		event_data.initiatingprocesssha256 = values['InitiatingProcessSHA256']
		event_data.initiatingprocessfilename = values['InitiatingProcessFileName']
		event_data.initiatingprocessid = values['InitiatingProcessId']
		event_data.initiatingprocesscommandline = values['InitiatingProcessCommandLine']
		event_data.initiatingprocesscreationtime = values['InitiatingProcessCreationTime']
		event_data.initiatingprocessfolderpath = values['InitiatingProcessFolderPath']
		event_data.initiatingprocessparentid = values['InitiatingProcessParentId']
		event_data.initiatingprocessparentfilename = values['InitiatingProcessParentFileName']
		event_data.initiatingprocessparentcreationtime = values['InitiatingProcessParentCreationTime']

		if len(values['AdditionalFields']) > 0 and "Command" in values['AdditionalFields']:
			addJson = json.loads(values['AdditionalFields'])
			event_data.powershellcommand = addJson['Command']
			
		else:
			event_data.powershellcommand = ""

		parser_mediator.ProduceEventData(event_data)

	def _ParseValuesProcessCreated(self, parser_mediator, values):
		"""Parses M365 Defender Advanced hunting values.

		Action type = ProcessCreated

		Args:
			values (list[str]): values extracted from the line.

		"""     
		resultTimeParse = self._TIMESTAMP.parseString(values['Timestamp'])        
		time_elements_structure = resultTimeParse['timestamp']

		event_data = DefenderAdvancedHuntingProcessCreatedEventData()
		event_data.timestamp = self._ParseTimeElements(time_elements_structure)
		event_data.deviceid = values['DeviceId']
		event_data.devicename = values['DeviceName']
		event_data.filename = values['FileName']
		event_data.folderpath = values['FolderPath']
		event_data.sha256 = values['SHA256']
		event_data.processid = values['ProcessId']
		event_data.processcommandline = values['ProcessCommandLine']
		event_data.processcreationtime = values['ProcessCreationTime']
		event_data.accountdomain = values['AccountDomain']
		event_data.accountname = values['AccountName']
		event_data.initiatingprocessaccountdomain = values['InitiatingProcessAccountDomain']
		event_data.initiatingprocessaccountname = values['InitiatingProcessAccountName']
		event_data.initiatingprocesssha256 = values['InitiatingProcessSHA256']
		event_data.initiatingprocessfilename = values['InitiatingProcessFileName']
		event_data.initiatingprocessid = values['InitiatingProcessId']
		event_data.initiatingprocesscommandline = values['InitiatingProcessCommandLine']
		event_data.initiatingprocesscreationtime = values['InitiatingProcessCreationTime']
		event_data.initiatingprocessfolderpath = values['InitiatingProcessFolderPath']
		event_data.initiatingprocessparentid = values['InitiatingProcessParentId']
		event_data.initiatingprocessparentfilename = values['InitiatingProcessParentFileName']
		event_data.initiatingprocessparentcreationtime = values['InitiatingProcessParentCreationTime']

		parser_mediator.ProduceEventData(event_data)

	def _ParseValuesProcessCreatedUsingWmiQuery(self, parser_mediator, values):
		"""Parses M365 Defender Advanced hunting values.

		Action type = ProcessCreatedUsingWmiQuery

		Args:
			values (list[str]): values extracted from the line.

		"""     
		resultTimeParse = self._TIMESTAMP.parseString(values['Timestamp'])        
		time_elements_structure = resultTimeParse['timestamp']

		event_data = DefenderAdvancedHuntingProcessCreatedUsingWmiQueryEventData()
		event_data.timestamp = self._ParseTimeElements(time_elements_structure)
		event_data.deviceid = values['DeviceId']
		event_data.devicename = values['DeviceName']
		event_data.initiatingprocessaccountdomain = values['InitiatingProcessAccountDomain']
		event_data.initiatingprocessaccountname = values['InitiatingProcessAccountName']
		event_data.additionalfields = values['AdditionalFields']        

		parser_mediator.ProduceEventData(event_data)
		
	def _ParseValuesServiceInstalled(self, parser_mediator, values):
		"""Parses M365 Defender Advanced hunting values.

		Action type = ServiceInstalled

		Args:
			values (list[str]): values extracted from the line.

		"""     
		resultTimeParse = self._TIMESTAMP.parseString(values['Timestamp'])        
		time_elements_structure = resultTimeParse['timestamp']

		event_data = DefenderAdvancedHuntingServiceInstalledEventData()
		event_data.timestamp = self._ParseTimeElements(time_elements_structure)
		event_data.deviceid = values['DeviceId']
		event_data.devicename = values['DeviceName']
		event_data.filename = values['FileName']
		event_data.folderpath = values['FolderPath']
		event_data.initiatingprocessaccountdomain = values['InitiatingProcessAccountDomain']
		event_data.initiatingprocessaccountname = values['InitiatingProcessAccountName']
		event_data.initiatingprocesssha256 = values['InitiatingProcessSHA256']
		event_data.initiatingprocessfilename = values['InitiatingProcessFileName']
		event_data.initiatingprocessid = values['InitiatingProcessId']
		event_data.initiatingprocesscommandline = values['InitiatingProcessCommandLine']
		event_data.initiatingprocesscreationtime = values['InitiatingProcessCreationTime']
		event_data.initiatingprocessfolderpath = values['InitiatingProcessFolderPath']
		event_data.initiatingprocessparentid = values['InitiatingProcessParentId']
		event_data.initiatingprocessparentfilename = values['InitiatingProcessParentFileName']
		event_data.initiatingprocessparentcreationtime = values['InitiatingProcessParentCreationTime']
		event_data.additionalfields = values['AdditionalFields']        

		parser_mediator.ProduceEventData(event_data)
		
	def ParseFileObject(self, parser_mediator, file_object):
		"""Parses M365 Defender Advanced hunting file.

		Args:
			parser_mediator (ParserMediator): mediates interactions between parsers and other components, such as storage and dfVFS.
			file_object (dfvfs.FileIO): file-like object.

		Raises:
			WrongParser: when the file cannot be parsed.
		"""

		if self._testing != 0 :
			logger.info('request for parse object ...')
		line_reader = text_file.TextFile(
			file_object, encoding='UTF-8', end_of_line='\r\n')

		try:
			if self._testing != 0 :
				logger.info('check header line ...')
			header_line = line_reader.readline()
			if self._testing != 0 :
				logger.info('header: {0!s}'.format(
					header_line))
				logger.info('parser: {0!s}'.format(
					self._HEADER_LINE))
			self._HEADER_LINE.parseString(header_line)

			if self._testing != 0 :
				logger.info('check data line ...')
			data_line = line_reader.readline()
			if self._testing != 0 :
				logger.info('data: {0!s}'.format(
					data_line))
				logger.info('parser: {0!s}'.format(
					self._DATA_LINE))
			self._DATA_LINE.parseString(data_line)

		except UnicodeDecodeError as exception:
			raise errors.WrongParser(
				'unable to read line with error: {0!s}'.format(
					exception))

		except pyparsing.ParseException as exception:
			raise errors.WrongParser(
				'unable to parse line with error: {0!s}'.format(
					exception))

		if self._testing != 0 :
			logger.info('generating whole csv ...')

		data_lines = line_reader.readlines()
		separator = '\r\n'
		csv_lines = header_line + "\r\n" + data_line + "\r\n" + separator.join(data_lines)
		
		if self._testing != 0 :
			logger.info('whole csv: {0!s}'.format(
				csv_lines))
			
		reader = csv.DictReader(io.StringIO(csv_lines))
		for row in reader:
			if self._testing != 0 :
				logger.info('row: {0!s}'.format(
					row))
			self._ParseValues(parser_mediator, row)

	def SetTest(self, value):
		self._testing = value

manager.ParsersManager.RegisterParser(DefenderAdvancedHuntingParser)

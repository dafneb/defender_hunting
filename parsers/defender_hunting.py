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

class DefenderAdvancedHuntingEventData(events.EventData):
    """Parser for M365 Defender Advanced hunting event data.

    Attributes:
        timestamp (dfdatetime): timestamp of event [required]
        deviceid (str): device id [required]
        devicename (str): device name [required]
        actiontype (str): type of event [required]
        filename (str): file name of process [optional]
        folderpath (str): folder path of process [optional]
        sha256 (str): sha256 of process file [optional]
        processid (str): process id (pid) [optional]
        processcommandline (str): command-line for process [optional]
        processcreationtime (str): date and time for process creation [optional]
        accountdomain (str): identity domain for process [optional]
        accountname (str): identity name for process [optional]
        initiatingprocessaccountdomain (str): identity domain for initiating process [optional]
        initiatingprocessaccountname (str): identity name for initiating process [optional]
        initiatingprocesssha256 (str): sha256 of initiating process file [optional]
        initiatingprocessfilename (str): file name of initiating process [optional]
        initiatingprocessid (str): initiating process id (ppid) [optional]
        initiatingprocesscommandline (str): command-line for initiating process [optional]
        initiatingprocesscreationtime (str): date and time for initiating process creation [optional]
        initiatingprocessfolderpath (str): folder path of initiating process [optional]
        initiatingprocessparentid (str): parent process id (pppid) [optional]
        initiatingprocessparentfilename (str): file name of parent process [optional]
        initiatingprocessparentcreationtime (str): date and time for parent process creation [optional]
        remoteip (str): remote ip address [optional]
        remoteport (str): remote port [optional]
        remoteurl (str): remote url address [optional]
        localip (str): local ip address [optional]
        localport (str): local port [optional]
        protocol (str): used protocol [optional]
        remotedevicename (str): device name of caller [optional]
        registrykey (str): registry key [optional]
        registryvaluename (str): registry value [optional]
        registryvaluedata (str): registry data [optional]
        fileoriginurl (str): original url of file [optional]
        fileoriginip (str): original ip of file [optional]
        powershellcommand (str): powershell command [additional value]
        dnsquery (str): dns query [additional value]
    """

    DATA_TYPE = 'defender:advanced_hunting:line'

    def __init__(self):
        """Initializes event data."""
        super(DefenderAdvancedHuntingEventData, self).__init__(data_type=self.DATA_TYPE)
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
        self.remoteip = None
        self.remoteport = None
        self.remoteurl = None
        self.localip = None
        self.localport = None
        self.protocol = None
        self.remotedevicename = None
        self.registrykey = None
        self.registryvaluename = None
        self.registryvaluedata = None
        self.fileoriginurl = None
        self.fileoriginip = None
        self.powershellcommand = None
        self.dnsquery = None

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
        try:
            year, month, day_of_month, hours, minutes, seconds = (
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

    def _ParseValues(self, values):
        """Parses M365 Defender Advanced hunting values.

        Args:
            values (list[str]): values extracted from the line.
        """

        if self._testing != 0 :
            logger.info('request for parse values ...')
            logger.info(values['ActionType'])

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

        data_lines = line_reader.readlines()
        separator = '\r\n'
        csv_lines = data_line + "\r\n" + separator.join(data_lines)
        
        if self._testing != 0 :
            logger.info('generating whole csv ...')
            logger.info('whole csv: {0!s}'.format(
                csv_lines))
        #reader = csv.DictReader(data_lines)
        #for row in reader:
        #    self._ParseValues(row)

    def SetTest(self, value):
        self._testing = value

manager.ParsersManager.RegisterParser(DefenderAdvancedHuntingParser)

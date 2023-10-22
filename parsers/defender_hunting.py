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
        timestamp (dfdatetime): timestamp of event [required]
        deviceid (str): device id [required]
        devicename (str): device name [required]
        filename (str): file name of process [optional]
        folderpath (str): folder path of process [optional]
        processcommandline (str): command-line for process [optional]
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
            raise errors.WrongParser(
                '¨Not allowed action: {0!s}'.format(
                    values['ActionType']))

        if values['ActionType'] == "AntivirusScanCompleted":
            self._ParseValuesAntivirusScanCompleted(parser_mediator, values)
            
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

import time
from extronlib_pro import (
    EthernetClientInterface,
    File,
    Wait,
    event,
)
from aes_tools import Encrypt, Decrypt, GetRandomKey
import re
import datetime
import json
from collections import defaultdict

from gs_tools import DecodeLiteral, HashableDict

RE_LIST_FILENAME = re.compile('(.*?\..*?) .{3}, .{1,2} .{3} .{4} .{2}:.{2}:.{2} GMT (\d{1,10})\r\n')

CALENDAR_REFRESH_TIME = 60 * 10

MEDIA_PRFIX = 'MEDIA/'

KEY_FILE_TYPE = File  # in production use RFile
if not KEY_FILE_TYPE.Exists('key.dat'):
    with KEY_FILE_TYPE('key.dat', mode='wb') as f:
        f.write(GetRandomKey())


def GetKey():
    with KEY_FILE_TYPE('key.dat', mode='rb') as f:
        return f.read()


class _Player:
    def __init__(self, connectionParameters, meta=None, manager=None):
        '''

        :param connectionParameters: dict
        :param meta:
        :param manager:
        '''
        self._meta = meta

        self._connectionParameters = connectionParameters

        self._manager = manager
        self._connectionStatus = None

    def Update(self, connectionParameters, meta):
        # override in subclass
        pass

    def SetMeta(self, key, value):
        if self._meta is None:
            self._meta = {key: value}
        else:
            self._meta[key] = value

    def GetMeta(self, key=None):
        if key is None:
            return self._meta

        if self._meta is None:
            return None

        return self._meta.get(key, None)

    def LoadFileToMemory(self, filePath):
        # override this with subclass
        raise NotImplementedError

    def FileExistsInMemory(self, filename):
        # override this with subclass
        raise NotImplementedError

    def PlayFile(self, filename):
        # override this with subclass
        raise NotImplementedError

    def Stop(self):
        # override this with subclass
        raise NotImplementedError

    def GetConnectionStatus(self):
        # override this with subclass
        return self._connectionStatus

    # def __del__(self):
    #     print('_Player.__del__')
    #     self._interface.Disconnect()

    def GetCurrentPlayingFile(self):
        # returns None if no file or str filename like 'imagefile.png'
        # override this with subclass
        raise NotImplementedError

    def DeleteAllFiles(self):
        # override this with subclass
        raise NotImplementedError

    def GetFileDuration(self, filename):
        # override this with subclass
        raise NotImplementedError

    def ClearAllFiles(self, filename):
        # override this with subclass
        raise NotImplementedError


class SMD202_Player(_Player):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._working = False
        self._forceStayConnected = False
        self._authenticated = False
        self._connectionStatus = None
        self._mac = None
        self._partNumber = None

        IPAddress = self._connectionParameters.get('IPAddress')
        IPPort = self._connectionParameters.get('IPPort')

        PlainPassword = self._connectionParameters.pop('PlainPassword', None)
        if PlainPassword is None:
            self._encryptedPassword = None
        else:
            self._encryptedPassword = Encrypt(PlainPassword, GetKey())

        self._interface = EthernetClientInterface(IPAddress, IPPort,
                                                  debug=True)  # smdModule.EthernetClass(IPAddress, IPPort)
        self._Status = defaultdict(lambda: defaultdict(lambda: None))
        self._InitInterfaceEvents()

        # Disable OSD
        self.SendAndWait('\rwD1*0WNDW\r', 1, deliTag='\r\n')

        # Disable progress bar
        self.SendAndWait('\rwD2*0WNDW\r', 1, deliTag='\r\n')

    def _InitInterfaceEvents(self):
        @event(self._interface, 'ReceiveData')
        def RxEvent(interface, data):
            print(self.IPAddress, 'Rx:', data)
            data = data.decode()

            if 'Password:' in data:
                print('Trying to send password')
                self._authenticated = False
                pw = self.GetPlainPassword()
                if pw is None:
                    print('Error no player pw')
                else:
                    print('538 pw=', pw)
                    self._interface.SendAndWait(pw + '\r', 0.1)

            elif 'Login Administrator' in data or 'Login User' in data:
                print('PLAYER AUTHENTICATED')
                self._authenticated = True
                self._interface.SendAndWait('w3cv\r', 0.1)

            elif 'Fld?' in data:
                raise IOError('Not enough space available on player.')

        @event(self._interface, ['Connected', 'Disconnected'])
        def ConnectionEvent(interface, state):
            print('151 SMD ConnectionEvent', state)
            self._WriteStatus('ConnectionStatus', state)

            if state == 'Connected':
                self._interface.SendAndWait('w3cv\r', 0.1)
                self._authenticated = True  # assume no password
            elif state == 'Disconnected':
                self._authenticated = False
                self._wait_InterfaceDisconnect.Cancel()

        self._wait_InterfaceDisconnect = Wait(
            CALENDAR_REFRESH_TIME / 2,
            self._Disconnect
        )
        self._wait_InterfaceDisconnect.Cancel()

    def GetPlainPassword(self):
        if self._encryptedPassword is None:
            return None
        else:
            return DecodeLiteral(Decrypt(self._encryptedPassword, GetKey()))

    def Update(self, newParamsDict, meta=None):
        '''
        Used to update the IP/IPPort/Password, etc
        :param newParamsDict:
        :param meta:
        :return:
        '''
        print('Update', newParamsDict, meta)
        print('195 Update Disconnect()')
        self._interface.Disconnect()

        self.connectionParameters.update(newParamsDict)

        IPAddress = self._connectionParameters.get('IPAddress')
        IPPort = self._connectionParameters.get('IPPort')

        PlainPassword = self._connectionParameters.pop('PlainPassword', None)
        # print('865 PlainPassword=', PlainPassword)
        if PlainPassword is None:
            self._encryptedPassword = None
        else:
            self._encryptedPassword = Encrypt(PlainPassword, GetKey())

        print('870 self._encryptedPassword=', self._encryptedPassword)

        self._interface = EthernetClientInterface(IPAddress, IPPort)  # smdModule.EthernetClass(IPAddress, IPPort)

        if meta is not None:
            if self._meta is None:
                self._meta = meta
            else:
                self._meta = HashableDict(self._meta) + HashableDict(meta)

        self._InitInterfaceEvents()

    def ReadStatus(self, c, q=HashableDict()):
        print('ReadStatus(', c, q)
        print('195 self._Status=', self._Status)
        ret = self._Status.copy()[c][q]
        print('222 ret=', ret)
        return ret

    def GetConnectionStatus(self):
        return self.ReadStatus('ConnectionStatus')

    def __iter__(self):
        yield 'ConnectionStatus', self.ReadStatus('ConnectionStatus')
        yield 'ID', id(self)
        yield 'Type', 'SMD 202' if self.PartNumber == '60-1306-01' else self.PartNumber
        yield 'IPAddress', self.IPAddress
        yield 'IPPort', self.IPPort
        yield 'MACAddress', self.MACAddress
        yield 'Encrypted Password', DecodeLiteral(
            self._encryptedPassword) if self._encryptedPassword is not None else None

        if self._meta is not None:
            for key, value in self._meta.items():
                if key != 'PlainPassword':
                    yield key, value

    def _WriteStatus(self, c, v, q=HashableDict()):
        print('216 SMD202_Player._WriteStatus', c, v, q)
        if q is None:
            q = {}

        q = HashableDict(q)
        if self._meta is not None:
            q += self._meta

        if self._manager is not None:
            self._manager._WriteStatus(c, v, q)

        self._Status[c][q] = v
        print('228 self_Status=', self._Status)

        if c == 'ConnectionStatus' and v == 'Disconnected':
            self._interface.CancelSend()

    @property
    def IPAddress(self):
        return self._interface.IPAddress

    @property
    def IPPort(self):
        return self._interface.IPPort

    def SendAndWait(self, *args, **kwargs):
        print('243 SendAndWait(', args, kwargs)

        startTime = time.time()
        while self._working:
            print('SendAndWait waiting to send')
            time.sleep(1)
            if time.time() - startTime > 3:
                print('SendAndWait timed out')
                return None

        self._Connect()
        connectResult = self._interface.Connect()
        print('280 connectResult=', connectResult)
        if 'Connected' not in connectResult:
            self._WriteStatus('ConnectionStatus', 'Disconnected')
            return None
        else:
            self._WriteStatus('ConnectionStatus', 'Connected')

        count = 0
        while self._authenticated is False:
            print('not authenticated')
            time.sleep(1)
            count += 1
            if count > 10:
                print('could not authenticate')
                return None
        print('authenticated')

        try:
            res = self._interface.SendAndWait(*args, **kwargs)
        except Exception as e:
            print('Exception 298:', e)
            self._WriteStatus('ConnectionStatus', 'Disconnected')
            return None

        print('262 res=', res)
        return res

    def _Connect(self):
        # connects if not connected already
        # automatically disconnects after X seconds of inactivity
        print('717 _Connect()')
        if self._authenticated is True:
            print('739 smd already connected')
            self._wait_InterfaceDisconnect.Restart()
            return 'Connected'

        res = self._interface.Connect(3)
        print('723 res=', res)
        self._WriteStatus('ConnectionStatus', 'Connected' if 'Connected' in res else 'Disconnected')
        if res != 'Connected':
            # raise RuntimeError('Could not connect to SMD 202 at IP={}: {}'.format(self.IPAddress, res))
            return 'Disconnected'

        time.sleep(1)  # allow time for authentication
        count = 0
        while self._authenticated is False:
            print('not authenticated')
            time.sleep(1)
            count += 1
            if count > 10:
                return 'Disconnected'

        self._wait_InterfaceDisconnect.Restart()

    def _Disconnect(self):
        print('SMD202_Player._Disconnect(), self._forceStayConnected=', self._forceStayConnected)
        if self._forceStayConnected is True:
            self._wait_InterfaceDisconnect.Restart()
        else:
            print('345 Disconnect()')
            self._interface.Disconnect()
            self._authenticated = False

    def FileExistsInMemory(self, filepath):
        print('295 FileExistInMemory(filepath={})'.format(filepath))

        res = self._Connect()

        ret = False

        try:
            print('639 self.authenticated=', self._authenticated)
            res = self._interface.SendAndWait('wlf\r', 3, deliTag='Bytes Left\r\n')
            print('621 FileExistInMemory res={}'.format(res))
            if res is not None:
                res = res.decode()

                for match in RE_LIST_FILENAME.finditer(res):
                    print('778 match.group(1)=', match.group(1))
                    name = match.group(1)
                    name = name.split('/')[-1]  # strip to only filepath, no rel path
                    print('781 name=', name)
                    if filepath.upper() == name.upper():
                        print('filepath.upper() == name.upper()')
                        print('filepath.upper()=', filepath.upper())
                        print('name.upper()=', name.upper())
                        ret = True
                        break
                else:
                    ret = False

        except Exception as e:
            print('FileExistInMemory Exception:', e)

        print('FileExistInMemory return', ret)
        return ret

    def PlayFile(self, localPath):
        # filepath should be like "filepath.png" without any rel path
        print('PlayFile(', localPath)
        filename = localPath.split('/')[-1]

        currentFile = self.GetCurrentPlayingFile()
        print('795 current playing File=', currentFile)
        if currentFile == filename:
            print('985 filepath "{}" is already playing.'.format(filename))
            return

        self._Connect()

        if filename.upper().endswith('.JSPF'):
            # This is a playlist. Load all nowItems from playlist also
            playlistPath = MEDIA_PRFIX + filename
            playlistObj = _Playlist(playlistPath)
            for thisFilePath in playlistObj.GetFilePaths():
                self.LoadFileToMemory(thisFilePath)

            self.LoadFileToMemory(localPath)

        else:
            # This is a single file (not a playlist)
            if not self.FileExistsInMemory(filename):
                self.LoadFileToMemory(localPath)

        res = self._interface.SendAndWait('wlf\r', 3, deliTag='Bytes Left\r\n')
        print('667 PlayFile res={}'.format(res))
        if res is not None:
            res = res.decode()
            filepath = None
            for match in RE_LIST_FILENAME.finditer(res):
                print('986 match.group(1)=', match.group(1))
                smdLocalPath = match.group(1)
                if filename == smdLocalPath.split('/')[-1]:
                    filepath = match.group(1)

            if filepath is not None:
                msg = 'wU{}*{}PLYR\r'.format(1, filepath)
                print('651 msg=', msg)
                self._interface.SendAndWait(msg, 0.1)
                time.sleep(5)  # give the SMD time to load the content
                self._interface.SendAndWait('wS1*1PLYR\x0D', 0.1)  # play the content
            else:
                raise KeyError(
                    '983 filepath is None. The desired file "{}" was not found on the player'.format(filepath))

    def Stop(self):
        print('Stop(', self)
        self._Connect()
        self._interface.SendAndWait('wO1PLYR\x0D', 0.1)  # stop

    def GetSizeOfFile(self, filepath):
        print('402 GetSizeOfFile(', filepath)
        if not self.FileExistsInMemory(filepath):
            raise FileNotFoundError(filepath)
        else:
            res = self.SendAndWait('\rwlf\r', 3, deliTag='Bytes Left\r\n')
            if res:
                res = res.decode()
                for match in RE_LIST_FILENAME.finditer(res):
                    thisPath = match.group(1)
                    if thisPath == filepath:
                        size = match.group(2)
                        return int(size)

    def VerifySize(self, filepath, size):
        print('415 VerifySize(', filepath, size)
        if size is not None:
            size = int(size)
        return self.GetSizeOfFile(filepath) == size

    def DeleteFileIfWrongSize(self, filepath, size):
        print('418 DeleteFileIfWrongSize(', filepath, size)
        if not self.VerifySize(filepath, size):
            self.DeleteFile(filepath)
            return True  # File was deleted
        return False

    def DeleteFile(self, filepath):
        print('423 DeleteFile(', filepath)
        res = self.SendAndWait('\rw{}EF\r', 3, deliTag='\r\n')
        print('423 DeleteFile res=', res)
        return res

    def LoadFileToMemory(self, localURI, progressCallback=None):
        # sends the file from the localURI to the player's internal memory
        print('LoadFileToMemory(', localURI)

        self._working = True

        if self.GetFreeSpace() < (500000000 * 0.9):
            # If remaining file space is less than 10% clear all files
            self.ClearAllFiles()

        remoteURI = localURI.split('/')[-1]
        self._forceStayConnected = True  # sometimes loading a large file can take a long time

        self._Connect()

        try:
            self._interface.SendAndWait('w3cv\r', 0.1)

            time.sleep(1)
            print('Sending to SMD')
            with File(localURI, mode='rb') as file:
                print('file=', file)
                fileSize = len(file.read())

                if fileSize == 0:
                    raise IOError('Invalid File size 0')

                print('fileSize=', fileSize)
                file.seek(0)
                time.sleep(0.1)
                msg = 'w+UF{},{}\r'.format(fileSize, remoteURI)
                print('msg=', msg)
                res = self._interface.SendAndWait(msg, 1, deliTag='\r\n')
                print('393', msg, 'res=', res)
                if 'Fld?' in res.decode():
                    raise IOError('Not enough space available on player.')
                time.sleep(0.1)
                print('394 Sending the file.read()')

                self._interface.Send(file.read(),
                                     progressCallback=progressCallback)
                self._working = False  # allow SendAndWaits to work again

                time.sleep(2)
                res = self._interface.SendAndWait('15i', 1, deliTag='\r\n')
                print('399 15i res=', res)
                time.sleep(5)
                print('401 done sending file')

                time.sleep(1)
                res = self._interface.SendAndWait('wR1*1PLYR\r', 1, deliTag='\r\n')
                print('405 wR1*1PLYR\r res=', res)

                # make sure the new file is the right size.. it may have gotten corrupted
                self.DeleteFileIfWrongSize(remoteURI, fileSize)

        except Exception as e:
            print('405 SendFileToSMD Exception:', e)

        self._forceStayConnected = False
        self._working = False

    def GetCurrentPlayingFile(self):
        print('GetCurrentPlayingFile')

        res = self.SendAndWait('\rwL1PLYR\r', 3, deliTag='\r\n')
        print('1078 res=', res)
        if res is None:
            return None
        else:
            print('883 res=', res)
            res = res.decode()
            res = res.strip()
            filename = res.split('/')[-1]  # this is the file that is loaded, but may not be playing

        res = self.SendAndWait('wY1PLYR\r', 3, deliTag='\r\n')
        print('1087 res=', res)
        if res is None:
            return None
        else:
            print('891 res=', res)
            res = res.decode()
            if 'PlyrY1*0' in res:
                return None
            elif 'PlyrY1*1' in res:
                print('1095 return filename=', filename)
                return filename
            else:
                print('1099 return None, res=', res)
                return None

    def _FreeSpace(self):
        # returns float() of remaining KB
        res = self.SendAndWait('15i', 3, deliTag='\r\n')
        if res:
            res = res.decode()
            blockSize = res.split('*')[1]
            freeBlocks = res.split('*')[3]
            freeBytes = int(blockSize) * int(freeBlocks)
            freeKBytes = freeBytes / 1024
            return freeKBytes  # return KB

    def DeleteAllFiles(self):
        self.SendAndWait('w//ef\r', 3, deliTag='\r\n')

    def GetFileDuration(self, filename):
        oldPlayingFile = self.GetCurrentPlayingFile()

        self.PlayFile(filename)
        time.sleep(1)

        res = self.SendAndWait('wZ1PLYR\r', 3, deliTag='\r\n')
        if res:
            res = res.decode()

            timeStr = res.split('*')[1]
            if timeStr == '\r\n':
                self.PlayFile(oldPlayingFile)
                return None
            else:
                timeStr = timeStr.strip()  # remove white space

            hour, min, secondWithMili = timeStr.split(':')
            second, milli = secondWithMili.split('.')

            hour = int(hour)
            min = int(min)
            second = int(second)
            milli = int(milli)

            print('hour={}, min={}, second={}, milli={}'.format(hour, min, second, milli))

            delta = datetime.timedelta(
                hours=hour,
                minutes=min,
                seconds=second,
                milliseconds=milli
            )

            return delta.total_seconds()

        self.PlayFile(oldPlayingFile)
        return None

    RE_BYTES_LEFT = re.compile('\r\n(\d+) Bytes Left\r\n')

    def GetFreeSpace(self):
        '''

        :return: int - number of bytes left
        '''
        res = self._interface.SendAndWait('wlf\r', 3, deliTag='Bytes Left\r\n')
        bytesLeft = None

        if res:
            print('res=', res)
            for match in self.RE_BYTES_LEFT.finditer(res.decode()):
                bytesLeft = int(match.group(1))

        if bytesLeft is None:
            print('Unknown file space remaining')
            return 0
        print('535 bytesLeft=', bytesLeft)
        return bytesLeft

    def ClearAllFiles(self):
        print('SMD ClearAllFiles')
        self.SendAndWait('\rw//EF\r', 1, deliTag='\r\n')

    @property
    def MACAddress(self):
        print('505 MACAddress')
        if self._mac is None:
            try:
                res = self.SendAndWait('\rwch\r', 1, deliTag='\r\n')
                print('566 res=', res)
                if res:
                    res = res.decode()
                    res = res.split(' ')[-1].strip()
                    self._mac = res
                    return res
            except Exception as e:
                print('516 Exception', e)
                return None
        else:
            return self._mac

    @property
    def PartNumber(self):
        print('575 PartNumber')
        if self._partNumber is None:
            try:
                res = self.SendAndWait('\rn', 1, deliTag='\r\n')
                print('580 res=', res)
                if res:
                    res = res.decode()
                    res = res.split(' ')[-1].strip().replace('Pno', '')
                    self._partNumber = res
                    return res
            except Exception as e:
                print('587 Exception', e)
                return None
        else:
            return self._partNumber

    # def __del__(self):
    #     print('SMD202_Player.__del__()')
    #     self._interface.Disconnect()

    def __str__(self):
        return '<SMD202_Player: IPAddress={}, IPPort={}>'.format(self.IPAddress, self.IPPort)


class _Playlist:
    # methods for easily creating/reading extron .jspf files

    @classmethod
    def GetExistingPlaylist(cls, filenames):
        # filenames is a list of str like ['myfile.png', 'otherfile.png']
        # returns _Playlist object if a playlist exists in processor memory that contains exactly these filenames (same order)
        for filepath in File.ListDirWithSub():
            thisFilename = filepath.split('/')[-1]
            if thisFilename.upper().endswith('.JSPF'):
                # this is a jspf playlist
                thisPlaylistObj = _Playlist(filepath)
                if thisPlaylistObj.GetFilePaths() == filenames:
                    print('1342 return thisPlaylistObj=', thisPlaylistObj)
                    return thisPlaylistObj

        return None

    def __init__(self, playlistFilePath=None):
        if playlistFilePath is None:

            self._data = defaultdict(
                lambda: {
                    'creator': 'ExtronProcessor',
                    'title': time.asctime(),
                    'track': [],
                    'x-extron-seamless': True,
                })

            self._filename = 'Playlist{}.jspf'.format(int(time.time()))
        else:
            self._ParseJSPF(playlistFilePath)

    def _ParseJSPF(self, filepath):
        print('_ParseJSPF')
        # popuplate class attributes with info from the .jspf file
        self._filename = filepath.split('/')[-1]
        with File(filepath, mode='rt') as file:
            self._data = json.loads(file.read())

    def GetPlaylistName(self):
        print('GetPlaylistName')
        return self._filename

    def GetFilePaths(self):
        '''

        :return: list of filepaths
        '''
        print('GetFilePaths')
        ret = []
        for trackD in self._data.get('playlist', {}).get('track', []):
            print('1376 trackD=', trackD)
            locationList = trackD.get('location')
            print('1379 locationList=', locationList)
            path = locationList[0]
            ret.append(path)

        print('1379 ret=', ret)
        return ret

    def AddFile(self, filepath, duration=7):
        print('AddFile', filepath)
        filename = filepath.split('/')[-1]

        self._data['playlist']['track'].append({
            'duration': duration * 1000,  # in miliseconds
            'location': ['file:///MEDIA/{}'.format(filename)],
            'title': 'Track {}'.format(len(self._data['playlist']['track']) + 1)
        })

    def Save(self, dir='/', filename=None):
        print('Save', dir, filename)
        # Saves the playlist .jspf file to processor memory
        if not dir.endswith('/'):
            dir += '/'

        if filename is None:
            filename = self._filename

        with File(dir + filename, mode='wt') as file:
            file.write(json.dumps(self._data, indent=2, sort_keys=True))

    def __str__(self):
        return '<{}, self._filename={}, self._data={}>'.format(repr(self), self._filename, self._data)


if __name__ == '__main__':
    from extronlib_pro import Timer

    player = SMD202_Player(
        connectionParameters={
            'IPAddress': '192.168.68.143',
            'IPPort': 23,
            'PlainPassword': 'grant',
        }
    )
    print('player.MACAddress=', player.MACAddress)
    # FILE = 'Extron_favicon_200px.png'
    # size = player.GetSizeOfFile(FILE)
    # print('size=', size)
    # res = player.VerifySize(FILE, size)
    # print('res=', res)

    t = Timer(1, lambda t, c: player.SendAndWait('q', 1))
    time.sleep(3)

    PATH_LOCAL = r'starwars-tvspot_h1080p.mov'
    player.LoadFileToMemory(PATH_LOCAL)

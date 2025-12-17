import random, aiohttp, ssl, time, os, urllib3
from packet import *
from cfonts import render, say
from Pb2 import MajorLogin_pb2, GetLoginData_pb2
from datetime import datetime
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# User credentials
USER_ID = "4298145841"
PASSWORD = "2_4RG3Q_BY_SPIDEERIO_GAMING_L3DCY"

Device_Model = None
Android_Version = None
Build_Number = None
Garena_Version = None
LoginUrl, ReleaseVersion, version, Version = "https://loginbp.ggpolarbear.com", "OB51", "1.118.1", "2019118695"
Hr = {'Connection': "Keep-Alive", 'Accept-Encoding': "gzip", 'Content-Type': "application/octet-stream", 'Expect': "100-continue", 'X-Unity-Version': "2018.4.11f1", 'X-GA': "v1 1", 'ReleaseVersion': ReleaseVersion, 'Content-Type': "application/x-www-form-urlencoded"}
async def encrypted_proto(encoded_data):
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(encoded_data, AES.block_size)
    encrypted_payload = cipher.encrypt(padded_message)
    return encrypted_payload
    
async def Required_For_User_Agent():
    global Device_Model, Android_Version, Build_Number, Garena_Version
    models = ['SM-A125F', 'SM-A225F', 'SM-A325M', 'SM-A515F', 'SM-A725F', 'SM-M215F', 'SM-M325FV', 'Redmi 9A', 'Redmi 9C', 'POCO M3', 'POCO M4 Pro', 'RMX2185', 'RMX3085', 'moto g(9) play', 'CPH2239', 'V2027', 'OnePlus Nord', 'ASUS_Z01QD']
    android_versions = ['9', '10', '11', '12', '13', '14']
    versions = ['4.0.18P6', '4.0.19P7', '4.0.20P1', '4.1.0P3', '4.1.5P2', '4.2.1P8', '4.2.3P1', '5.0.1B2', '5.0.2P4', '5.1.0P1', '5.2.0B1', '5.2.5P3', '5.3.0B1', '5.3.2P2', '5.4.0P1', '5.4.3B2', '5.5.0P1', '5.5.2P3']
    build_numbers = {'9': ['PKQ1.190616.001', 'PPR1.180610.011', 'PQ3B.190801.10101846'], '10': ['QP1A.190711.020', 'QKQ1.191014.001', 'QQ3A.200805.001'], '11': ['RP1A.200720.011', 'RP1A.200720.012', 'RKQ1.200826.002'], '12': ['SP1A.210812.016', 'SQ1D.220205.004', 'SKQ1.210216.001'], '13': ['TP1A.220624.014', 'TQ1A.221205.011', 'TQ2A.230505.002'], '14': ['UP1A.231005.007', 'UQ1A.231205.015', 'UQ2A.240205.004']}
    if Device_Model is None:
        Device_Model = random.choice(models)
        Android_Version = random.choice(android_versions)
        Build_Number = random.choice(build_numbers[Android_Version])
        Garena_Version = random.choice(versions)

async def Login_And_Other_User_Agent():
    await Required_For_User_Agent()
    return f"Dalvik/2.1.0 (Linux; U; Android {Android_Version}; {Device_Model} Build/{Build_Number})"

async def Connect_Garana_User_Agent():
    await Required_For_User_Agent()
    lang_country = {'en-US': 'USA', 'es-MX': 'MEX', 'pt-BR': 'BRA', 'id-ID': 'IDN', 'ru-RU': 'RUS', 'hi-IN': 'IND'}
    lang = random.choice(list(lang_country.keys()))
    country = lang_country[lang]
    return f"GarenaMSDK/{Garena_Version}({Device_Model};Android {Android_Version};{lang};{country};)"
    
async def MajorLogin(Payload):
    try:
        url = f"{LoginUrl}/MajorLogin"
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        Hr['User-Agent'] = (await Login_And_Other_User_Agent())
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=Payload, headers=Hr, ssl=ssl_context) as response:
                if response.status == 200: return await response.read()
                return None
    except Exception as e:
        print(f"MajorLogin Error: {e}")
        return None
async def GetLoginData(URL, Payload, Token):
    try:
        url = f"{URL}/GetLoginData"
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        Hr['Authorization']= f"Bearer {Token}"
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=Payload, headers=Hr, ssl=ssl_context) as response:
                if response.status == 200: return await response.read()
                return None
    except Exception as e:
        print(f"GetLoginData Error: {e}")
        return None
    
async def DecryptMajorLogin(MajorLoginResponse):
    try:
        proto = MajorLogin_pb2.MajorLoginRes()
        proto.ParseFromString(MajorLoginResponse)
        return proto
    except Exception as e:
        print(f"DecryptMajorLogin Error: {e}")
        return None
    
async def DecryptGetLoginData(GetLoginDataResponse):
    try:
        proto = GetLoginData_pb2.GetLoginData()
        proto.ParseFromString(GetLoginDataResponse)
        return proto
    except Exception as e:
        print(f"DecryptMajorLogin Error: {e}")
        return None
    
async def FinalTokenToGetOnline(Target, Token, Timestamp, key, iv):
   try:
       UidHex = hex(Target)[2:]
       UidLength = len(UidHex)
       EncryptedTimeStamp = await DecodeHex(Timestamp)
       EncryptedAccountToken = Token.encode().hex()
       EncryptedPacket = await EncryptPacket(EncryptedAccountToken, key, iv)
       EncryptedPacketLength = hex(len(EncryptedPacket) // 2)[2:]
       if UidLength == 9: headers = '0000000'
       elif UidLength == 8: headers = '00000000'
       elif UidLength == 10: headers = '000000'
       elif UidLength == 7: headers = '000000000'
       else: print('Unexpected length'); headers = '0000000'
       return f"0115{headers}{UidHex}{EncryptedTimeStamp}00000{EncryptedPacketLength}{EncryptedPacket}"
   except Exception as e:
        print(f"FinalTokenToGetOnline Error: {e}")
        return None
async def EncryptLoginPayload(open_id, access_token):
    try:
        fields = {
            3: str(datetime.now())[:-7],
            4: "free fire", 
            5: 1,
            7: version,
            8: "Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)",
            9: "Handheld",
            10: "Verizon",
            11: "WIFI",
            12: 1920,
            13: 1080,
            14: "280",
            15: "ARM64 FP ASIMD AES VMH | 2865 | 4",
            16: 3003,
            17: "Adreno (TM) 640",
            18: "OpenGL ES 3.1 v1.46",
            19: "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57",
            20: "223.191.51.89",
            21: "en",
            22: open_id,
            23: "4",
            24: "Handheld",
            25: "07@Q",
            29: access_token,
            30: 1,
            41: "Verizon",
            42: "WIFI",
            57: "7428b253defc164018c604a1ebbfebdf",
            60: 36235,
            61: 31335,
            62: 2519,
            63: 703,
            64: 25010,
            65: 26628,
            66: 32992,
            67: 36235,
            73: 3,
            74: "/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/lib/arm64",
            76: 1,
            77: "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/base.apk",
            78: 3,
            79: 2,
            81: "64",
            83: Version,
            86: "OpenGLES2",
            87: 16383,
            88: 4,
            89: b"FwQVTgUPX1UaUllDDwcWCRBpWA0UOQsVAVsnWlBaO1kFYg==",
            92: 13564,
            93: "android",
            94: "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY=",
            95: 110009,
            97: 1,
            98: 1,
            99: "4",
            100: "4"
        }
        return (await encrypted_proto(await CreateProtobufPacket(fields)))
    except Exception as e:
        print(f"EncryptLoginPayload Error: {e}")
        return None
    
async def GeNeRaTeAccEss(Uid , Password):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": (await Connect_Garana_User_Agent()),
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"}
    data = {
        "uid": Uid,
        "password": Password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"}
    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=headers, data=data) as response:
            if response.status != 200: return await response.read()
            data = await response.json()
            open_id = data.get("open_id")
            access_token = data.get("access_token")
            return (open_id, access_token) if open_id and access_token else (None, None)
            
class FF_CLIENT:
    def __init__(self):
        self.key = None
        self.iv = None
        self.BotUid = None
        self.BotToken = None
        self.URL = None
        self.InvitePlayerId = None
        self.StatusData = None
        self.SquadData = None
        self.MatchmakingData = None
        
    async def SendPacket(self, Packet):
        self.online_writer.write(Packet); await self.online_writer.drain()
        
    async def InviteAcceptedRejectedStatus(self):
        if self.SquadData != None:
            InviteData = json.loads(self.SquadData)
            if '4' in InviteData and InviteData['4']['data'] == 2:
                self.SquadData = None
                return await self.InviteAcceptedRejectedStatus()
            elif '4' in InviteData and InviteData['4']['data'] == 50 and '5' in InviteData:
                return InviteData
            elif '4' in InviteData and InviteData['4']['data'] == 6 and '5' in InviteData:
                return InviteData
        else:
            await asyncio.sleep(1)
            return await self.InviteAcceptedRejectedStatus()
        
    async def MatchmakingStatus(self):
        if self.MatchmakingData != None:
            MatchStartData = json.loads(self.MatchmakingData)
            self.MatchmakingData = None
            if "4" in MatchStartData and MatchStartData["4"]["data"] == 5:
                return MatchStartData
            elif "5" in MatchStartData and "data" in MatchStartData["5"] and "2" in MatchStartData["5"]["data"] and "data" in MatchStartData["5"]["data"]["2"] and MatchStartData["5"]["data"]["2"]["data"] == 43:
                print("Lone Wolf matchmaking")
                return await self.MatchmakingStatus()
            else:
                return await self.MatchmakingStatus()
        else:
            await asyncio.sleep(0.1)
            return await self.MatchmakingStatus()
        
    async def SlwdLoop(self, FinalTokn):
        while True:
            try:
                if self.online_writer is None or self.online_writer.is_closing():
                    print("Writer not available, waiting...")
                    await asyncio.sleep(5)
                    continue
                StatusPlayerId = await PlayerStatus(self.InvitePlayerId, self.key, self.iv)
                StatusPlayerIdResponse = await self.SendPacket(StatusPlayerId)
                await asyncio.sleep(1)
                if self.StatusData != None:
                    StatusData = json.loads(self.StatusData)
                    if "5" in StatusData and "data" in StatusData["5"] and "1" in StatusData["5"]["data"] and "data" in StatusData["5"]["data"]["1"] and isinstance(StatusData["5"]["data"]["1"]["data"], dict) and "3" in StatusData["5"]["data"]["1"]["data"]:
                        if "3" in StatusData["5"]["data"]["1"]["data"] and "data" in StatusData["5"]["data"]["1"]["data"]["3"] and StatusData["5"]["data"]["1"]["data"]["3"]["data"] == 1 and "11" in StatusData["5"]["data"]["1"]["data"] and "data" in StatusData["5"]["data"]["1"]["data"]["11"] and StatusData["5"]["data"]["1"]["data"]["11"]["data"] == 1:
                            print("Any mode ready to team solo")
                            LoneWolfMode = await SwitchLoneWolf(self.key, self.iv)
                            LoneWolfModeResponse = await self.SendPacket(LoneWolfMode)
                            await asyncio.sleep(1)
                            LoneWolfModeDuel = await SwitchLoneWolfDule(self.BotUid, self.key, self.iv)
                            LoneWolfModeDuelResponse = await self.SendPacket(LoneWolfModeDuel)
                            await asyncio.sleep(1)
                            InvitePlayerId = await InvitePlayer(self.InvitePlayerId, self.key, self.iv)
                            InvitePlayerIdResponse = await self.SendPacket(InvitePlayerId)
                            await asyncio.sleep(1)
                            StartLoneWolf = await StartGame(self.BotUid, self.key, self.iv)
                            StartLoneWolfResponse = await self.SendPacket(StartLoneWolf)
                            MatchStartData = await self.MatchmakingStatus()
                            if "4" in MatchStartData and MatchStartData["4"]["data"] == 5:
                                print("Match found")
                                if "5" in MatchStartData and "data" in MatchStartData["5"]:
                                     server_data = MatchStartData["5"]["data"]
                                     if "7" in server_data and server_data["7"]["data"] == 43:
                                         game_mode = "LONE WOLF"
                                         print(f"GAME MODE: {game_mode}")
                                await asyncio.sleep(30)
                                print("DEBUG: 30-second delay finished")
                                return
                            else:
                                print("Match Data Not Found")
                                await asyncio.sleep(30)
                        elif "3" in StatusData["5"]["data"]["1"]["data"] and "data" in StatusData["5"]["data"]["1"]["data"]["3"] and StatusData["5"]["data"]["1"]["data"]["3"]["data"] == 2 and "11" in StatusData["5"]["data"]["1"]["data"] and "data" in StatusData["5"]["data"]["1"]["data"]["11"] and StatusData["5"]["data"]["1"]["data"]["11"]["data"] == 1 and "9" in StatusData["5"]["data"]["1"]["data"] and "data" in StatusData["5"]["data"]["1"]["data"]["9"] and "10" in StatusData["5"]["data"]["1"]["data"] and "data" in StatusData["5"]["data"]["1"]["data"]["10"] and StatusData["5"]["data"]["1"]["data"]["10"]["data"] + 1 != StatusData["5"]["data"]["1"]["data"]["9"]["data"] and StatusData["5"]["data"]["1"]["data"]["9"]["data"] == 1:
                            print("In group only one playe")
                            LoneWolfMode = await SwitchLoneWolf(self.key, self.iv)
                            LoneWolfModeResponse = await self.SendPacket(LoneWolfMode)
                            await asyncio.sleep(1)
                            InvitePlayerId = await InvitePlayer(self.InvitePlayerId, self.key, self.iv)
                            InvitePlayerIdResponse = await self.SendPacket(InvitePlayerId)
                            await asyncio.sleep(1)
                            if self.SquadData != None:
                                SquadData = json.loads(self.SquadData)
                                if '4' in SquadData and SquadData['4']['data'] == 2:
                                    print("Invite Sent")
                                    await asyncio.sleep(1)
                                    InviteStatus = await self.InviteAcceptedRejectedStatus()
                                    if '4' in InviteStatus and InviteStatus['4']['data'] == 6 and '5' in InviteStatus:
                                        KickFixGlitch = await GlitchFixKick(self.InvitePlayerId, self.key, self.iv)
                                        KickFixGlitchResponse = await self.SendPacket(KickFixGlitch)
                                        print("Kicked")
                                        await asyncio.sleep(1)
                                        SwitchSolo= await LeaveTeam(self.BotUid, self.key, self.iv)
                                        SwitchSoloResponse = await self.SendPacket(SwitchSolo)
                                        print("Leave Team")
                                        self.StatusData = None
                                    elif '4' in InviteStatus and InviteStatus['4']['data'] == 50 and '5' in InviteStatus:
                                        print("Rejected")
                                        SwitchSolo= await LeaveTeam(self.BotUid, self.key, self.iv)
                                        SwitchSoloResponse = await self.SendPacket(SwitchSolo)
                                        print("Waiting for 10-second to be in solo mode")
                                        self.StatusData = None
                                        await asyncio.sleep(10)
                                else:
                                    InviteStatus = await self.InviteAcceptedRejectedStatus()
                                    if '4' in InviteStatus and InviteStatus['4']['data'] == 6 and '5' in InviteStatus:
                                        KickFixGlitch = await GlitchFixKick(self.InvitePlayerId, self.key, self.iv)
                                        KickFixGlitchResponse = await self.SendPacket(KickFixGlitch)
                                        print("Kicked")
                                        await asyncio.sleep(1)
                                        SwitchSolo= await LeaveTeam(self.BotUid, self.key, self.iv)
                                        SwitchSoloResponse = await self.SendPacket(SwitchSolo)
                                        print("Leave Team")
                                        self.StatusData = None
                                    elif '4' in InviteStatus and InviteStatus['4']['data'] == 50 and '5' in InviteStatus:
                                        print("Rejected")
                                        SwitchSolo= await LeaveTeam(self.BotUid, self.key, self.iv)
                                        SwitchSoloResponse = await self.SendPacket(SwitchSolo)
                                        print("Waiting for 10-second to be in solo mode")
                                        self.StatusData = None
                                        await asyncio.sleep(10)
                        elif "3" in StatusData["5"]["data"]["1"]["data"] and "data" in StatusData["5"]["data"]["1"]["data"]["3"] and StatusData["5"]["data"]["1"]["data"]["3"]["data"] == 2 and "11" in StatusData["5"]["data"]["1"]["data"] and "data" in StatusData["5"]["data"]["1"]["data"]["11"] and StatusData["5"]["data"]["1"]["data"]["11"]["data"] == 1 and "9" in StatusData["5"]["data"]["1"]["data"] and "data" in StatusData["5"]["data"]["1"]["data"]["9"] and "10" in StatusData["5"]["data"]["1"]["data"] and "data" in StatusData["5"]["data"]["1"]["data"]["10"] and StatusData["5"]["data"]["1"]["data"]["10"]["data"] + 1 == StatusData["5"]["data"]["1"]["data"]["9"]["data"]:
                            print("Team Full")
                            LoneWolfMode = await SwitchLoneWolf(self.key, self.iv)
                            LoneWolfModeResponse = await self.SendPacket(LoneWolfMode)
                            await asyncio.sleep(1)
                            InvitePlayerId = await InvitePlayer(self.InvitePlayerId, self.key, self.iv)
                            InvitePlayerIdResponse = await self.SendPacket(InvitePlayerId)
                            await asyncio.sleep(1)
                            if self.SquadData != None:
                                SquadData = json.loads(self.SquadData)
                                if '4' in SquadData and SquadData['4']['data'] == 2:
                                    print("Invite Sent")
                                    InviteStatus = await self.InviteAcceptedRejectedStatus()
                                    await asyncio.sleep(1)
                                    if '4' in InviteStatus and InviteStatus['4']['data'] == 6 and '5' in InviteStatus:
                                        KickFixGlitch = await GlitchFixKick(self.InvitePlayerId, self.key, self.iv)
                                        KickFixGlitchResponse = await self.SendPacket(KickFixGlitch)
                                        print("Kicked")
                                        await asyncio.sleep(1)
                                        SwitchSolo= await LeaveTeam(self.BotUid, self.key, self.iv)
                                        SwitchSoloResponse = await self.SendPacket(SwitchSolo)
                                        print("Leave Team")
                                        self.StatusData = None
                                    elif '4' in InviteStatus and InviteStatus['4']['data'] == 50 and '5' in InviteStatus:
                                        print("Rejected")
                                        SwitchSolo= await LeaveTeam(self.BotUid, self.key, self.iv)
                                        SwitchSoloResponse = await self.SendPacket(SwitchSolo)
                                        print("Waiting for 10-second to be in solo mode")
                                        self.StatusData = None
                                        await asyncio.sleep(10)
                                else:
                                    InviteStatus = await self.InviteAcceptedRejectedStatus()
                                    if '4' in InviteStatus and InviteStatus['4']['data'] == 6 and '5' in InviteStatus:
                                        KickFixGlitch = await GlitchFixKick(self.InvitePlayerId, self.key, self.iv)
                                        KickFixGlitchResponse = await self.SendPacket(KickFixGlitch)
                                        print("Kicked")
                                        await asyncio.sleep(1)
                                        SwitchSolo= await LeaveTeam(self.BotUid, self.key, self.iv)
                                        SwitchSoloResponse = await self.SendPacket(SwitchSolo)
                                        print("Leave Team")
                                        self.StatusData = None
                                    elif '4' in InviteStatus and InviteStatus['4']['data'] == 50 and '5' in InviteStatus:
                                        print("Rejected")
                                        SwitchSolo= await LeaveTeam(self.BotUid, self.key, self.iv)
                                        SwitchSoloResponse = await self.SendPacket(SwitchSolo)
                                        print("Waiting for 10-second to be in solo mode")
                                        self.StatusData = None
                                        await asyncio.sleep(10)
                        else:
                            print("No condition matched")
                            self.StatusData = None
                    else:
                        print("No condition matched")
                        self.StatusData = None
                else:
                    print("Status Data: None")
                    self.StatusData = None
            except Exception as e:
                print(f"- Error With SlwdLoop - {e}")
                await asyncio.sleep(5)
        
    async def TcpOnline(self, FinalTokn):
        PlayCount = 0
        while True:
            try:
                reader , writer = await asyncio.open_connection(self.OnlineIP, int(self.OnlinePort))
                self.online_writer = writer
                BytesPayload = bytes.fromhex(FinalTokn)
                self.online_writer.write(BytesPayload)
                await self.online_writer.drain()
                await asyncio.sleep(1)
                SlwdLoop = asyncio.create_task(self.SlwdLoop(FinalTokn))
                while True:
                    self.data2 = await reader.read(9999)
                    
                    data2 = self.data2
                    if not data2: break
                    if self.data2:
                        if self.data2.hex().startswith("0300"):
                            self.MatchmakingData = await DecodeProtobufPacket(self.data2.hex()[10:])
                            
                        if self.data2.hex().startswith("0500"):
                            self.SquadData = await DecodeProtobufPacket(self.data2.hex()[10:])
                            
                        if self.data2.hex().startswith("0f00"):
                            self.StatusData = await DecodeProtobufPacket(self.data2.hex()[10:])
                           
                    if SlwdLoop.done():
                        result = SlwdLoop.result()
                        PlayCount += 1
                        print(f"Total Game Played: {PlayCount}")
                        break
            except Exception as e: print(f"- Error With {self.OnlineIP}:{int(self.OnlinePort)} - {e}"); self.online_writer = None
            await asyncio.sleep(0.5)
            if 'SlwdLoop' in locals() and not SlwdLoop.done():
                SlwdLoop.cancel()
                try:
                    await SlwdLoop
                except asyncio.CancelledError:
                    pass
        
    async def Main(self):
        Uid = '4215946226'; Password = 'B8C01D45B946C06302C97CF29A8355D6B2C0F78293AECC4AAEB9B5AF616950B5'
        if self.InvitePlayerId == None:
            self.InvitePlayerId = input("EnTer Uid To STarT LvL Up! : ")
        open_id, access_token = await GeNeRaTeAccEss(Uid, Password)
        if not open_id or not access_token: print("Error - Invalid Account"); return None
        Payload = await EncryptLoginPayload(open_id, access_token)
        self.LoginPayload = Payload
        MajorLoginResponse = await MajorLogin(Payload)
        if not MajorLoginResponse: print("Target Account => Banned/Not Registered ! "); return None
        MajorLoginDecrypt = await DecryptMajorLogin(MajorLoginResponse)
        Target = MajorLoginDecrypt.account_uid
        self.BotUid = Target
        Token = MajorLoginDecrypt.token
        self.BotToken = Token
        Url = MajorLoginDecrypt.url
        self.URL = Url
        self.key = MajorLoginDecrypt.key
        self.iv = MajorLoginDecrypt.iv
        TimeStamp = MajorLoginDecrypt.timestamp
        GetLoginDataResponse = await GetLoginData(Url, Payload, Token)
        if not GetLoginDataResponse: print("Error - Geting Ports From Login Data !"); return None
        GetLoginDataDecrypt = await DecryptGetLoginData(GetLoginDataResponse)
        Region = GetLoginDataDecrypt.Region
        AccountName = GetLoginDataDecrypt.AccountName
        OnlinePorts = GetLoginDataDecrypt.Online_IP_Port
        ChaPorts = GetLoginDataDecrypt.AccountIP_Port
        self.OnlineIP , self.OnlinePort = OnlinePorts.split(":")
        self.ChatIP , self.ChatPort = ChaPorts.split(":")
        FinalToken = await FinalTokenToGetOnline(int(Target), Token, int(TimeStamp), self.key, self.iv)
        TcpOnline = asyncio.create_task(self.TcpOnline(FinalToken))
        os.system('cls') if os.name == 'nt' else os.system('clear')
        print(render('ARYAN', colors=['white', 'red'], align='center'))
        print(f" - Server Login Url => {LoginUrl} Server Url => {Url}\n")
        print(f" - Game status > Good | OB => {ReleaseVersion} | Version => {version}\n")
        print(f" - Bot Starting And Online on Target : {AccountName} | Uid : {Target} | Region => {Region}\n")
        print(f" - Bot status > Good | Online ! (:\n")
        await asyncio.gather(TcpOnline)
        
client = FF_CLIENT()
async def Starting():
    while True:
        try: await asyncio.wait_for(client.Main() , timeout = 7 * 60 * 60)
        except asyncio.TimeoutError: print("Token ExpiRed ! , ResTartinG")
        except Exception as e:import traceback; print(f"ErroR TcP - {e} => ResTarTinG ...");traceback.print_exc()

if __name__ == '__main__':
    asyncio.run(Starting())
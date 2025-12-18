from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from protobuf_decoder.protobuf_decoder import Parser
import asyncio
import json

async def EncryptPacket(hex_data, key=None, iv=None):
    try:
        default_key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
        default_iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
        encryption_key = key if key else default_key
        encryption_iv = iv if iv else default_iv
        cipher = AES.new(encryption_key, AES.MODE_CBC, encryption_iv)
        cipher_text = cipher.encrypt(pad(bytes.fromhex(hex_data), AES.block_size))
        return cipher_text.hex()
    except ValueError as e:
        raise ValueError(f"Invalid hex data: {e}")
    except Exception as e:
        raise Exception(f"Encryption failed: {e}")

async def DecodeHex(number):
    try:
        hex_string = hex(number)[2:]
        return hex_string.zfill(2)
    except (TypeError, ValueError) as e:
        raise ValueError(f"Invalid number for hex conversion: {e}")

async def EncodeVarint(number):
    if not isinstance(number, int) or number < 0:
        raise ValueError("Number must be a non-negative integer")
    encoded_bytes = []
    while True:
        byte = number & 0x7F
        number >>= 7
        if number:
            byte |= 0x80
        encoded_bytes.append(byte)
        if not number:
            break
    return bytes(encoded_bytes)

async def CreateVarintField(field_number, value):
    try:
        field_header = (field_number << 3) | 0
        header_bytes = await EncodeVarint(field_header)
        value_bytes = await EncodeVarint(value)
        return header_bytes + value_bytes
    except Exception as e:
        raise ValueError(f"Failed to create varint field: {e}")

async def CreateLengthDelimitedField(field_number, value):
    try:
        field_header = (field_number << 3) | 2
        encoded_value = value.encode('utf-8') if isinstance(value, str) else value
        header_bytes = await EncodeVarint(field_header)
        length_bytes = await EncodeVarint(len(encoded_value))
        return header_bytes + length_bytes + encoded_value
    except Exception as e:
        raise ValueError(f"Failed to create length delimited field: {e}")

async def CreateProtobufPacket(fields):
    try:
        packet = bytearray()
        for field_number, value in fields.items():
            if isinstance(value, dict):
                nested_packet = await CreateProtobufPacket(value)
                field_bytes = await CreateLengthDelimitedField(field_number, nested_packet)
                packet.extend(field_bytes)
            elif isinstance(value, int):
                field_bytes = await CreateVarintField(field_number, value)
                packet.extend(field_bytes)
            elif isinstance(value, (str, bytes)):
                field_bytes = await CreateLengthDelimitedField(field_number, value)
                packet.extend(field_bytes)
        return bytes(packet)
    except Exception as e:
        raise ValueError(f"Failed to create protobuf packet: {e}")
    
async def ParseResults(parsed_results):
    try:
        result_dict = {}
        for result in parsed_results:
            field_data = {'wire_type': result.wire_type}
            if result.wire_type in ["varint", "string"]:
                field_data['data'] = result.data
            elif result.wire_type == 'length_delimited':
                field_data["data"] = await ParseResults(result.data.results)
            result_dict[result.field] = field_data
        return result_dict
    except Exception as e:
        raise ValueError(f"Failed to parse results: {e}")
    
async def DecodeProtobufPacket(hex_data):
    try:
        parsed_results = Parser().parse(hex_data)
        parsed_results_dict = await ParseResults(parsed_results)
        return json.dumps(parsed_results_dict)
    except Exception as e:
        raise ValueError(f"Failed to decode protobuf packet: {e}")
    
async def GlitchFixKick(player_id, key, iv):
    fields = {1: 35, 2: {1: int(player_id)}}
    return await GenPacket((await CreateProtobufPacket(fields)).hex(), '0519', key, iv)
    
async def LeaveTeam(bot_uid, key, iv):
    fields = {1: 7, 2: {1: bot_uid}}
    return await GenPacket((await CreateProtobufPacket(fields)).hex(), '0519', key, iv)
    
async def StartGame(bot_uid, key, iv):
    fields = {1: 9, 2: {1: bot_uid}}
    return await GenPacket((await CreateProtobufPacket(fields)).hex(), '0519', key, iv)
    
async def SwitchLoneWolfDuel(bot_uid, key, iv):
    fields = {1: 17, 2: {1: bot_uid, 2: 1, 3: 1, 4: 43, 5: "\u000b", 8: 1, 19: 1}}
    return await GenPacket((await CreateProtobufPacket(fields)).hex(), '0519', key, iv)
    
async def InvitePlayer(player_id, key, iv):
    fields = {1: 2, 2: {1: int(player_id), 2: "ME", 4: 1}}
    return await GenPacket((await CreateProtobufPacket(fields)).hex(), '0519', key, iv)
    
async def PlayerStatus(player_id, key, iv):
    fields = {1: 1, 2: {1: int(player_id), 5: 1}}
    return await GenPacket((await CreateProtobufPacket(fields)).hex(), '0F19', key, iv)
    
async def SwitchLoneWolf(key, iv):
    fields = {1: 1, 2: {2: "\u000b", 3: 43, 4: 1, 5: "en", 9: 1, 10: "\u0001\t\n\u000b\u0012\u0019\u001a ", 11: 1, 13: 1, 14: {2: 86, 6: 11, 8: "1.118.10", 9: 3, 10: 1}}}
    return await GenPacket((await CreateProtobufPacket(fields)).hex(), '0519', key, iv)

async def SwitchClashSquad(bot_uid, key, iv):
    fields = {1: 17, 2: {1: bot_uid, 2: 1, 3: 1, 4: 44, 5: "\u000b", 8: 1, 19: 1}}
    return await GenPacket((await CreateProtobufPacket(fields)).hex(), '0519', key, iv)

async def StartClashSquadMatch(bot_uid, key, iv):
    fields = {1: 9, 2: {1: bot_uid, 2: 44}}
    return await GenPacket((await CreateProtobufPacket(fields)).hex(), '0519', key, iv)

async def PlayerMovement(player_id, x_pos, y_pos, z_pos, key, iv):
    fields = {1: 20, 2: {1: int(player_id), 2: int(x_pos), 3: int(y_pos), 4: int(z_pos), 5: 1}}
    return await GenPacket((await CreateProtobufPacket(fields)).hex(), '0619', key, iv)

async def DealDamage(attacker_id, target_id, damage_amount, key, iv):
    fields = {1: 25, 2: {1: int(attacker_id), 2: int(target_id), 3: int(damage_amount), 4: 1}}
    return await GenPacket((await CreateProtobufPacket(fields)).hex(), '0719', key, iv)

async def ShootPlayer(shooter_id, target_id, key, iv):
    fields = {1: 30, 2: {1: int(shooter_id), 2: int(target_id), 3: 100}}
    return await GenPacket((await CreateProtobufPacket(fields)).hex(), '0719', key, iv)

async def CheckMatchStatus(player_id, key, iv):
    fields = {1: 40, 2: {1: int(player_id)}}
    return await GenPacket((await CreateProtobufPacket(fields)).hex(), '0819', key, iv)

async def RestartMatch(bot_uid, key, iv):
    fields = {1: 45, 2: {1: bot_uid, 2: 1}}
    return await GenPacket((await CreateProtobufPacket(fields)).hex(), '0519', key, iv)

async def AutoPlayLoop(bot_uid, player_id, key, iv, match_type='clash_squad'):
    while True:
        try:
            if match_type == 'clash_squad':
                await SwitchClashSquad(bot_uid, key, iv)
                await asyncio.sleep(2)
                await StartClashSquadMatch(bot_uid, key, iv)
            else:
                await StartGame(bot_uid, key, iv)
            
            await asyncio.sleep(5)
            
            x, y, z = 100, 100, 0
            for _ in range(50):
                x += 5
                y += 3
                await PlayerMovement(player_id, x, y, z, key, iv)
                await asyncio.sleep(0.5)
                
                if _ % 10 == 0:
                    await ShootPlayer(player_id, player_id + 1, key, iv)
                    await asyncio.sleep(0.3)
            
            await asyncio.sleep(10)
            await CheckMatchStatus(player_id, key, iv)
            await asyncio.sleep(3)
            await RestartMatch(bot_uid, key, iv)
            await asyncio.sleep(5)
            
        except Exception as e:
            print(f"Match error: {e}, restarting...")
            await asyncio.sleep(10)
            continue

async def PickupWeapon(player_id, weapon_id, key, iv):
    fields = {1: 50, 2: {1: int(player_id), 2: int(weapon_id)}}
    return await GenPacket((await CreateProtobufPacket(fields)).hex(), '0A19', key, iv)

async def ReloadWeapon(player_id, key, iv):
    fields = {1: 55, 2: {1: int(player_id)}}
    return await GenPacket((await CreateProtobufPacket(fields)).hex(), '0A19', key, iv)

async def UseHealthKit(player_id, key, iv):
    fields = {1: 60, 2: {1: int(player_id), 2: 1}}
    return await GenPacket((await CreateProtobufPacket(fields)).hex(), '0B19', key, iv)

async def ReviveTeammate(player_id, teammate_id, key, iv):
    fields = {1: 65, 2: {1: int(player_id), 2: int(teammate_id)}}
    return await GenPacket((await CreateProtobufPacket(fields)).hex(), '0C19', key, iv)

async def SendTeamMessage(player_id, message, key, iv):
    fields = {1: 70, 2: {1: int(player_id), 2: str(message)}}
    return await GenPacket((await CreateProtobufPacket(fields)).hex(), '0D19', key, iv)

async def ChangeWeapon(player_id, weapon_slot, key, iv):
    fields = {1: 75, 2: {1: int(player_id), 2: int(weapon_slot)}}
    return await GenPacket((await CreateProtobufPacket(fields)).hex(), '0A19', key, iv)

async def Crouch(player_id, key, iv):
    fields = {1: 80, 2: {1: int(player_id), 2: 1}}
    return await GenPacket((await CreateProtobufPacket(fields)).hex(), '0619', key, iv)

async def Jump(player_id, key, iv):
    fields = {1: 85, 2: {1: int(player_id)}}
    return await GenPacket((await CreateProtobufPacket(fields)).hex(), '0619', key, iv)

async def AdvancedBotLoop(bot_uid, player_id, key, iv):
    try:
        await SwitchClashSquad(bot_uid, key, iv)
        await asyncio.sleep(2)
        await StartClashSquadMatch(bot_uid, key, iv)
        await asyncio.sleep(5)
        
        x, y, z = 100, 100, 0
        for i in range(100):
            x += 3
            y += 2
            await PlayerMovement(player_id, x, y, z, key, iv)
            
            if i % 5 == 0:
                await PickupWeapon(player_id, 101, key, iv)
            if i % 15 == 0:
                await ShootPlayer(player_id, player_id + 1, key, iv)
                await ReloadWeapon(player_id, key, iv)
            if i % 20 == 0:
                await UseHealthKit(player_id, key, iv)
            if i % 10 == 0:
                await Crouch(player_id, key, iv)
            
            await asyncio.sleep(0.3)
        
        await CheckMatchStatus(player_id, key, iv)
        await asyncio.sleep(5)
        await RestartMatch(bot_uid, key, iv)
        return True
    except Exception as e:
        raise ValueError(f"Advanced bot loop failed: {e}")

async def GenPacket(packet, header_type, key, iv):
    try:
        encrypted_packet = await EncryptPacket(packet, key, iv)
        length_hex = await DecodeHex(len(encrypted_packet) // 2)
        
        padding_map = {2: "000000", 3: "00000", 4: "0000", 5: "000"}
        padding = padding_map.get(len(length_hex), "")
        
        if not padding:
            raise ValueError(f"Unsupported packet length: {len(length_hex)}")
            
        header = header_type + padding
        return bytes.fromhex(header + length_hex + encrypted_packet)
    except Exception as e:
        raise ValueError(f"Failed to generate packet: {e}")

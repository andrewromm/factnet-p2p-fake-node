import time
import hashlib
from datetime import datetime
import binascii


def mess_handshake(peer_name):
    message_type = (0).to_bytes(1, byteorder='big')
    version = (1).to_bytes(4, byteorder='big')
    timestamp = (int(round(time.time() * 1000))).to_bytes(8, byteorder='big')
    peer_name = peer_name.encode('utf-8')
    message_length = (4+8+2+len(peer_name)).to_bytes(4, byteorder='big')
    message_body = version + timestamp + (len(peer_name)*8).to_bytes(2, byteorder='big') + peer_name
    checksum = hashlib.sha256(hashlib.sha256(message_body).digest()).digest()[:4]
    return message_type + message_length + message_body + checksum


def read_message(msg):
    message_type = int.from_bytes(msg[:1], byteorder='big')
    message_length = int.from_bytes(msg[1:5], byteorder='big')
    message = f"Received msg, length: {message_length}, type_code: {message_type}"
    data = {}
    if message_type == 0:
        version = int.from_bytes(msg[5:8], byteorder='big')
        timestamp = int.from_bytes(msg[10:17], byteorder='big')
        peer_name_length = int(int.from_bytes(msg[17:19], byteorder='big')/8)
        peer_name = msg[19:19+peer_name_length].decode('utf-8')
        message += f" handshake: from: {peer_name}, version: {version}, datetime: {datetime.fromtimestamp(timestamp/1000.0).strftime('%d.%m.%Y %H:%M:%S')}"
    elif message_type == 2:
        array_length = int.from_bytes(msg[5:7], byteorder='big')
        addresses = []
        start_index = 7
        for _ in range(array_length):
            addr_length = int.from_bytes(msg[start_index:start_index+1], byteorder='big')
            addr = ''.join(
                f"{int.from_bytes(msg[i:i+1], byteorder='big')}."
                for i in range(start_index + 1, start_index + 1 + addr_length)
            )
            addr = addr[:-1]
            addr += f":{int.from_bytes(msg[start_index+1+addr_length:start_index+1+addr_length+4], byteorder='big')}"
            addresses.append(addr)
            start_index = start_index+1+addr_length+4
        message += f" peers [{array_length}]: {', '.join(addresses)}"
    elif message_type == 3:
        request_id = msg[5:37]
        # тут может быть массив тэгов, но системой не предусмотрено
        tag_length = int(int.from_bytes(msg[39:41], byteorder='big')/8)
        tag = msg[41:41+tag_length].decode('utf-8')
        ttl = int.from_bytes(msg[41+tag_length:41+tag_length+4], byteorder='big')
        data = {
            'requestId': request_id
        }
        message += f" tag: {tag}, ttl: {ttl}, requestId: {binascii.hexlify(request_id)}"
    return {
        'message': message,
        'data': data
    }


def mess_get_peers(max_peers):
    message_type = (1).to_bytes(1, byteorder='big')
    max_peers = (max_peers).to_bytes(4, byteorder='big')
    message_length = (4).to_bytes(4, byteorder='big')
    message_body = max_peers
    checksum = hashlib.sha256(hashlib.sha256(message_body).digest()).digest()[:4]
    return message_type + message_length + message_body + checksum


def mess_send_facts(facts, request_id):
    message_type = (4).to_bytes(1, byteorder='big')
    
    facts_length = len(facts).to_bytes(2, byteorder='big')
    facts_bytes = facts_length
    for item in facts:
        fact_length = (len(item['fact'])*8).to_bytes(2, byteorder='big')
        tags_length = len(item['tags']).to_bytes(2, byteorder='big')
        tags_bytes = tags_length
        for tag in item['tags']:
            tag_length = (len(tag)*8).to_bytes(2, byteorder='big')
            tags_bytes += tag_length + tag.encode('utf-8')
        facts_bytes += fact_length + item['fact'].encode('utf-8') + tags_bytes

    message_length = (len(request_id)+len(facts_bytes)).to_bytes(4, byteorder='big')
    message_body = request_id + facts_bytes
    checksum = hashlib.sha256(hashlib.sha256(message_body).digest()).digest()[:4]
    return message_type + message_length + message_body + checksum
import socket
import binascii
from messages import mess_handshake, mess_get_peers, mess_send_facts, read_message

NODE_NAME = 'node7'
BUFFER_SIZE = 10240
MAX_PEERS = 10
# Сведения о другой ноде
EXTERNAL_NODE_ADDRESS = ('127.0.0.1', 9031)

FAKE_FACTS = [
    {
        "fact": "bitcoin is underrated",
        "tags": [
            "bitcoin",
            "animal"
        ]
    }
]

def init_node(node_name, external_node_address):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(external_node_address)

    try: 
        # Отправляем handshake
        s.send(mess_handshake(node_name))
        data = s.recv(BUFFER_SIZE)
        if data:
            print(read_message(data)['message'])
            # Запрашиваем и получаем пиры
            s.send(mess_get_peers(MAX_PEERS))
            data = s.recv(BUFFER_SIZE)
            if data:
                print(read_message(data)['message'])
                return s
        else:
            return None
    except socket.error: 
        print(socket.error)  
    
    return None


if __name__ == '__main__':
    print("Node is running, please, press ctrl+c to stop")
    try:
        node = init_node(NODE_NAME, EXTERNAL_NODE_ADDRESS)
        if not node:
            print("Can't connect to external node. Node stopped!")
            exit()

        while node:
            data = node.recv(BUFFER_SIZE)
            message = read_message(data)['message']
            print(message)
            data = read_message(data)['data']
            # Если в запросе пришел requestId отправляем фековые данные
            if 'requestId' in data:
                try:
                    node.send(mess_send_facts(FAKE_FACTS, request_id=data['requestId']))
                    print(f"Fake data was sent for requestId: {binascii.hexlify(data['requestId'])}")
                except socket.error: 
                    print(socket.error) 
    except KeyboardInterrupt:
        print("Node stopped! Thank you for using!")

import logging
import asyncio
import socket
from kademlia.network import Server

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
kademlia_logger = logging.getLogger('kademlia')
kademlia_logger.setLevel(logging.DEBUG)
kademlia_logger.addHandler(logging.StreamHandler())

server = None


async def initialize_dht():
    global server
    server = Server()
    await server.listen(8470)
    await server.bootstrap([("127.0.0.1", 8470)])


async def set_value(key, value):
    await server.set(key, value)


async def get_value(key):
    try:
        return await server.get(key)
    except Exception as e:
        return str(e)


def socket_server():
    HOST = '127.0.0.1'
    PORT = 65432

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()

        print("Socket server started and listening on {}:{}".format(HOST, PORT))

        while True:
            conn, addr = s.accept()
            with conn:
                data = conn.recv(1024)
                if not data:
                    break

                parts = data.decode().split(',')
                command = parts[0]

                if command == "set":
                    key, value = parts[1], parts[2]
                    asyncio.run(set_value(key, value))
                    response = "Credential status set successfully."

                elif command == "revoke":
                    key, value = parts[1], parts[2]
                    asyncio.run(set_value(key, value))
                    response = "Credential revoked successfully."

                elif command == "get":
                    key = parts[1]
                    response = asyncio.run(get_value(key))
                else:
                    response = "Invalid command."

                conn.sendall(response.encode())


async def main():
    await initialize_dht()
    print("Kademlia server initialized.")

    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, socket_server)

    try:
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        pass

    print("Kademlia server closed.")
    server.stop()


if __name__ == "__main__":
    asyncio.run(main())

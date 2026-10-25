"""Ephemeral loopback mTLS public gateway reference, PGW1 framing.

Unknown/internal failures close the connection. That is an observable failure,
not a privacy-preserving universal error claim or an execution outcome.
"""
import hashlib
import socket
import socketserver
import struct
import threading
import time

from public_gateway import MAX_FRAME,response
from delivery_transport import public
from ledger import Rejected
from witness_transport import tls_context,certificate_fingerprint,read_exact,remaining


def recv_packet(channel,deadline):
    header=read_exact(channel,8,deadline)
    if header[:4]!=b'PGW1':raise Rejected('GW_FRAME')
    size=struct.unpack('>I',header[4:])[0]
    if not 1<=size<=MAX_FRAME:raise Rejected('GW_FRAME')
    return read_exact(channel,size,deadline)


def send_packet(channel,raw,deadline):
    if type(raw) is not bytes or not 1<=len(raw)<=MAX_FRAME:raise Rejected('GW_FRAME')
    channel.settimeout(remaining(deadline));channel.sendall(b'PGW1'+struct.pack('>I',len(raw))+raw)


class PublicGatewayTLSService:
    def __init__(self,*,ledger_factory,cafile,certfile,keyfile,signer,fault=lambda p:None):
        self.context=tls_context(cafile,certfile,keyfile,True);self.factory=ledger_factory;self.signer=signer;self.fault=fault
        ledger=ledger_factory()
        try:
            config=ledger.gateway_config()
            if config['certificate']!=certificate_fingerprint(certfile) or config['public_key']!=public(signer):raise Rejected('GW_SERVER_IDENTITY')
        finally:ledger.close()
        outer=self
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                deadline=time.monotonic()+5
                try:
                    self.request.settimeout(remaining(deadline))
                    with outer.context.wrap_socket(self.request,server_side=True) as channel:
                        peer=hashlib.sha256(channel.getpeercert(binary_form=True)).digest()
                        raw=recv_packet(channel,deadline);ledger=outer.factory()
                        try:reply=ledger.handle_public(raw,peer,outer.signer,outer.fault)
                        finally:ledger.close()
                        outer.fault('before_public_reply_send');send_packet(channel,reply,deadline)
                except (OSError,Rejected):return
        class Server(socketserver.ThreadingMixIn,socketserver.TCPServer):
            daemon_threads=True
            def handle_error(self,request,client_address):pass
        self.server=Server(('127.0.0.1',0),Handler);self.port=self.server.server_address[1];self.thread=None

    def __enter__(self):
        self.thread=threading.Thread(target=self.server.serve_forever,kwargs={'poll_interval':0.05},daemon=True);self.thread.start();return self

    def __exit__(self,*args):
        self.server.shutdown();self.server.server_close();self.thread.join(timeout=5)


class PublicGatewayClient:
    def __init__(self,*,port,cafile,certfile,keyfile,server_certificate,server_public_key,server_kid,deployment,timeout=5):
        if type(port) is not int or not 1<=port<=65535 or type(timeout) not in (float,int) or not 0<timeout<=30:raise ValueError('invalid endpoint')
        self.port=port;self.timeout=timeout;self.context=tls_context(cafile,certfile,keyfile)
        self.pin=server_certificate;self.public_key=server_public_key;self.kid=server_kid;self.deployment=deployment;self.last_tls_version=None

    def exchange(self,raw):
        deadline=time.monotonic()+self.timeout
        with socket.create_connection(('127.0.0.1',self.port),timeout=remaining(deadline)) as sock:
            sock.settimeout(remaining(deadline))
            with self.context.wrap_socket(sock,server_hostname='localhost') as channel:
                self.last_tls_version=channel.version()
                if hashlib.sha256(channel.getpeercert(binary_form=True)).digest()!=self.pin:raise Rejected('GW_SERVER_IDENTITY')
                send_packet(channel,raw,deadline);reply=recv_packet(channel,deadline)
                response(reply,raw,self.public_key,self.kid,self.deployment)
                return reply

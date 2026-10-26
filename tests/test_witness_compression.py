"""Both strict codec negatives and the existing RPC security suite in WRZ1 mode."""
import io
from pathlib import Path
import struct
import sys
import time
import unittest
from unittest.mock import patch
import zlib

P=Path(__file__).resolve().parents[1]/'outputs/agent-cryptography-design-20261025/prototype'
sys.path.insert(0,str(P))
import test_witness_transport as original
from witness_transport import frame_functions,receive_frame
from witness_compression import (compress_body,decompress_body,encode_frame,
    receive_compressed_frame,send_compressed_frame,MAX_ENCODED)
from witnessed_ledger import MAX_IMAGE,Rejected,image_hash


class BufferSocket:
    def __init__(self,data=b''):self.input=io.BytesIO(data);self.output=b'';self.reads=[]
    def settimeout(self,value):pass
    def recv(self,size):self.reads.append(size);return self.input.read(size)
    def sendall(self,data):self.output+=data


class CompressionCodecTests(unittest.TestCase):
    def test_round_trip_empty_small_and_maximum_image(self):
        for body in (b'',b'x',bytes(range(256))*100,b'a'*MAX_IMAGE):
            with self.subTest(size=len(body)):
                raw=encode_frame(b'metadata',body)
                meta,recovered=receive_compressed_frame(BufferSocket(raw),time.monotonic()+5)
                self.assertEqual((meta,recovered),(b'metadata',body))
                if body:self.assertEqual(image_hash(recovered),image_hash(body))

    def test_incompressible_image_can_expand_without_changing_bytes(self):
        body=bytes(range(256))
        encoded=compress_body(body)
        self.assertGreater(len(encoded),len(body))
        self.assertEqual(decompress_body(encoded,len(body)),body)

    def test_corruption_truncation_trailing_and_concatenated_streams_reject(self):
        good=zlib.compress(b'x'*100)
        for encoded in (b'garbage',good[:-1],good+b'x',good+good,good[:-1]+bytes([good[-1]^1])):
            with self.subTest(encoded=encoded):
                with self.assertRaisesRegex(Rejected,'INVALID_WITNESS_COMPRESSION'):
                    decompress_body(encoded,100)

    def test_dishonest_lengths_and_compressed_bomb_reject(self):
        for encoded,size in ((zlib.compress(b'x'*100),99),(zlib.compress(b'x'*100),101),
                             (zlib.compress(b'x'*MAX_IMAGE),1),
                             (zlib.compress(b''),0),(b'',1)):
            with self.subTest(size=size):
                with self.assertRaisesRegex(Rejected,'INVALID_WITNESS_COMPRESSION'):
                    decompress_body(encoded,size)

    def test_limits_checked_before_reading_payload(self):
        for sizes in ((0,0,0),(8193,0,0),(1,MAX_ENCODED+1,1),(1,1,MAX_IMAGE+1)):
            sock=BufferSocket(b'WRZ1'+struct.pack('>III',*sizes))
            with self.assertRaisesRegex(Rejected,'WITNESS_FRAME_LIMIT'):
                receive_compressed_frame(sock,time.monotonic()+5)
            self.assertEqual(sock.reads,[16])
        for body in (b'a'*(MAX_IMAGE+1),bytearray(b'a')):
            with self.assertRaises(Rejected):compress_body(body)
        for size in (-1,MAX_IMAGE+1,True):
            with self.assertRaises(Rejected):decompress_body(b'x',size)
        with self.assertRaises(Rejected):encode_frame(b'm'*8193,b'')

    def test_no_implicit_negotiation_or_fallback(self):
        raw=b'WRP1'+struct.pack('>II',8,0)+b'metadata'
        with self.assertRaisesRegex(Rejected,'INVALID_WITNESS_FRAME'):
            receive_compressed_frame(BufferSocket(raw),time.monotonic()+5)
        with self.assertRaisesRegex(Rejected,'INVALID_WITNESS_FRAME'):
            receive_frame(BufferSocket(encode_frame(b'metadata',b'')),time.monotonic()+5)
        for mode in ('auto','gzip','',None,[]):
            with self.assertRaises(ValueError):frame_functions(mode)

    def test_deadline_checked_after_codec_cpu_before_send_and_return(self):
        sock=BufferSocket()
        with patch('witness_transport.remaining',side_effect=[1,TimeoutError('deadline')]):
            with self.assertRaises(TimeoutError):send_compressed_frame(sock,b'm',b'x',0)
        self.assertEqual(sock.output,b'')
        sock=BufferSocket(encode_frame(b'm',b'x'))
        # Header, metadata, body reads, pre-decode and post-decode checks.
        with patch('witness_transport.remaining',side_effect=[1,1,1,1,TimeoutError('deadline')]):
            with self.assertRaises(TimeoutError):receive_compressed_frame(sock,0)


class CompressedTransportTests(unittest.TestCase):
    # Run established security/recovery behaviors through the same exact client
    # class in compressed mode. No weaker alternate ledger/client implementation.
    setUpClass=classmethod(original.TransportTests.setUpClass.__func__)
    tearDownClass=classmethod(original.TransportTests.tearDownClass.__func__)
    tearDown=original.TransportTests.tearDown
    reject=original.TransportTests.reject
    initialize=original.TransportTests.initialize
    setup_ledger=original.TransportTests.setup_ledger

    def setUp(self):
        original.TransportTests.setUp(self)
        self.server.frame_mode='deflate-v1'

    def client(self,role,**kwargs):
        kwargs.setdefault('frame_mode','deflate-v1')
        return original.TransportTests.client(self,role,**kwargs)

    def test_mismatched_bootstrap_mode_fails_without_committing(self):
        for server_mode,client_mode in (('raw','deflate-v1'),('deflate-v1','raw')):
            with self.subTest(server_mode=server_mode):
                self.server.frame_mode=server_mode
                client=self.client('admin',frame_mode=client_mode)
                with self.assertRaises((OSError,Rejected)):client.bootstrap(self.ns,b'initial')
                matching=self.client('admin',frame_mode=server_mode)
                self.reject('WITNESS_UNINITIALIZED',lambda:matching.head(self.ns))
        self.server.frame_mode='deflate-v1'


for name in dir(original.TransportTests):
    if name.startswith('test_') and name!='test_frame_lengths_are_bounded_before_body_allocation':
        setattr(CompressedTransportTests,name,getattr(original.TransportTests,name))

if __name__=='__main__':unittest.main()

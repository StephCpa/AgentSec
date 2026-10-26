"""Opt-in, bounded zlib witness body framing; never changes canonical images.

WRZ1 is selected by trusted bootstrap on both endpoints. Metadata, signatures,
image hashes and witness storage continue to use the uncompressed bytes. Length
and CPU timing are observable; this codec provides no padding/privacy guarantee.
"""
import struct
import zlib

from witnessed_ledger import MAX_IMAGE,Rejected

MAGIC=b'WRZ1'
HEADER_SIZE=16
MAX_ENCODED=MAX_IMAGE+65536
LEVEL=6


def validate_sizes(meta_size,encoded_size,raw_size):
    from witness_transport import MAX_META
    if (not 1<=meta_size<=MAX_META or not 0<=encoded_size<=MAX_ENCODED or
            not 0<=raw_size<=MAX_IMAGE):
        raise Rejected('WITNESS_FRAME_LIMIT')
    if (raw_size==0)!=(encoded_size==0):raise Rejected('INVALID_WITNESS_COMPRESSION')


def compress_body(body):
    if type(body) is not bytes or len(body)>MAX_IMAGE:raise Rejected('WITNESS_FRAME_LIMIT')
    encoded=zlib.compress(body,LEVEL) if body else b''
    if len(encoded)>MAX_ENCODED:raise Rejected('WITNESS_FRAME_LIMIT')
    return encoded


def decompress_body(encoded,raw_size):
    if type(encoded) is not bytes or type(raw_size) is not int:raise Rejected('WITNESS_FRAME_LIMIT')
    validate_sizes(1,len(encoded),raw_size)
    if not raw_size:return b''
    try:
        decoder=zlib.decompressobj()
        # The extra byte detects dishonest lengths, without allocating the full
        # output of a compressed bomb. Never call unbounded flush/decompress.
        body=decoder.decompress(encoded,raw_size+1)
    except zlib.error as exc:
        raise Rejected('INVALID_WITNESS_COMPRESSION') from exc
    if (len(body)!=raw_size or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail):
        raise Rejected('INVALID_WITNESS_COMPRESSION')
    return body


def encode_frame(meta,body):
    from witness_transport import MAX_META
    if type(meta) is not bytes or not 1<=len(meta)<=MAX_META:raise Rejected('WITNESS_FRAME_LIMIT')
    encoded=compress_body(body)
    return MAGIC+struct.pack('>III',len(meta),len(encoded),len(body))+meta+encoded


def send_compressed_frame(sock,meta,body,deadline):
    from witness_transport import remaining
    remaining(deadline)
    frame=encode_frame(meta,body)
    sock.settimeout(remaining(deadline));sock.sendall(frame)


def receive_compressed_frame(sock,deadline):
    from witness_transport import read_exact,remaining
    header=read_exact(sock,HEADER_SIZE,deadline)
    if header[:4]!=MAGIC:raise Rejected('INVALID_WITNESS_FRAME')
    meta_size,encoded_size,raw_size=struct.unpack('>III',header[4:])
    validate_sizes(meta_size,encoded_size,raw_size)
    meta=read_exact(sock,meta_size,deadline);encoded=read_exact(sock,encoded_size,deadline)
    remaining(deadline);body=decompress_body(encoded,raw_size);remaining(deadline)
    return meta,body

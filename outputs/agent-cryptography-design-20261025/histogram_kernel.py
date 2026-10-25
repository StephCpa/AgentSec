"""Fixed-public-work histogram kernel, trusted/synthetic inputs only.

No ledger integration, contribution preprocessing, physical constant-time claim,
or public endpoint. Ideal independent random bits are the statistical-DP model.
The full random tape must be durably admitted before any private read in a future
integration; a fixed 32-byte seed is NOT treated as arbitrarily many ideal bits.
"""
import secrets

MECHANISM='bounded_geometric_histogram_v1_candidate'
K_PROFILE=40
MAX_BUCKETS=64
MAX_CAPACITY=65535


def dimensions(bucket_count,k):
    if type(bucket_count) is not int or not 1<=bucket_count<=MAX_BUCKETS:
        raise ValueError('invalid public bucket count')
    if type(k) is not int or not 1<=k<=64:raise ValueError('invalid public K')
    bits=2*k*bucket_count
    return bits,(bits+7)//8


def validate_tape(tape,bucket_count,k):
    bits,size=dimensions(bucket_count,k)
    if type(tape) is not bytes or len(tape)!=size:raise ValueError('invalid tape length')
    padding=8*size-bits
    if padding and tape[-1]&((1<<padding)-1):raise ValueError('noncanonical tape padding')


def fresh_tape(bucket_count,k=K_PROFILE,randbytes=secrets.token_bytes):
    bits,size=dimensions(bucket_count,k);raw=randbytes(size)
    if type(raw) is not bytes or len(raw)!=size:raise ValueError('invalid random source output')
    padding=8*size-bits
    if padding:raw=raw[:-1]+bytes([raw[-1]&~((1<<padding)-1)])
    validate_tape(raw,bucket_count,k);return raw


def pack_bits(bits):
    if not bits or any(type(x) is not int or x not in (0,1) for x in bits):raise ValueError('invalid bits')
    output=bytearray((len(bits)+7)//8)
    for i,bit in enumerate(bits):output[i//8]|=bit<<(7-i%8)
    return bytes(output)


def decode_result(raw,bucket_count,capacity):
    dimensions(bucket_count,K_PROFILE)
    if type(capacity) is not int or not 1<=capacity<=MAX_CAPACITY:raise ValueError('invalid public capacity')
    if type(raw) is not bytes or len(raw)!=8*bucket_count:raise ValueError('invalid result width')
    values=tuple(int.from_bytes(raw[i:i+8],'big') for i in range(0,len(raw),8))
    if any(x>capacity for x in values):raise ValueError('result out of bounds')
    return values


class HistogramJob:
    """B blocks of N scan + 2K bit reads + 1 clip/store, fixed by public inputs.

    0 denotes an empty public slot; 1..B denotes one user's chosen public bucket.
    Private per-user deduplication/stable classification are upstream preconditions.
    Constructor validation is trusted ingestion, not an observable query handler.
    """
    def __init__(self,rows,tape,*,capacity,buckets,k=K_PROFILE):
        if type(buckets) not in (list,tuple):raise ValueError('invalid public buckets')
        if (any(type(x) is not str or not 1<=len(x.encode('utf-8'))<=64 for x in buckets) or
                len(set(buckets))!=len(buckets)):raise ValueError('invalid public buckets')
        dimensions(len(buckets),k)
        if type(capacity) is not int or not 1<=capacity<=MAX_CAPACITY:raise ValueError('invalid public capacity')
        if type(rows) not in (list,tuple) or len(rows)!=capacity:raise ValueError('invalid padded snapshot')
        if any(type(x) is not int or not 0<=x<=len(buckets) for x in rows):raise ValueError('invalid categorical slot')
        validate_tape(tape,len(buckets),k)
        self.rows=tuple(rows);self.tape=tape;self.n=capacity;self.buckets=tuple(buckets);self.k=k
        self.block=capacity+2*k+1;self.work=len(buckets)*self.block;self.pc=0
        self._counts=[0]*len(buckets);self._alive=[[1,1] for _ in buckets];self._g=[[0,0] for _ in buckets]
        self._outputs=[0]*len(buckets);self.result=None

    def public_position(self):
        if self.pc==self.work:return ('done',len(self.buckets),0)
        bucket,offset=divmod(self.pc,self.block)
        if offset<self.n:return ('scan',bucket,offset)
        if offset<self.n+2*self.k:return ('bit',bucket,offset-self.n)
        return ('store',bucket,0)

    def step(self):
        if self.pc>=self.work:raise ValueError('job already complete')
        phase,bucket,index=self.public_position()
        if phase=='scan':self._counts[bucket]+=int(self.rows[index]==bucket+1)
        elif phase=='bit':
            bit_index=bucket*2*self.k+index;bit=(self.tape[bit_index//8]>>(7-bit_index%8))&1
            side=index//self.k;self._alive[bucket][side]&=bit;self._g[bucket][side]+=self._alive[bucket][side]
        else:
            self._outputs[bucket]=min(self.n,max(0,self._counts[bucket]+self._g[bucket][0]-self._g[bucket][1]))
        self.pc+=1
        if self.pc==self.work:self.result=b''.join(x.to_bytes(8,'big') for x in self._outputs)
        return self.pc==self.work

    def run(self):
        while self.pc<self.work:self.step()
        return self.result

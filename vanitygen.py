# The MIT License (MIT)
#
# Copyright (c) 2011-2014 Erik Henriksson
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

from pywallet import *
from operator import mod
from multiprocessing import Process, Value
import time

# Config vars
THREADS = 8
SEARCH_STRING = "1abcd"

# secp256k1

_p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2FL
_r = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141L
_b = 0x0000000000000000000000000000000000000000000000000000000000000007L
_a = 0x0000000000000000000000000000000000000000000000000000000000000000L
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798L
_Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8L


def point_to_public_key(point):
	# public keys are 65 bytes long (520 bits)
	# 0x04 + 32-byte X-coordinate + 32-byte Y-coordinate
	hex_i2o_key = '04' + \
		'%064x' % point.x() + \
		'%064x' % point.y()
	return hex_i2o_key.decode('hex')

def point_to_private_key(point, secret):
	# private keys are 279 bytes long (see crypto/ec/cec_asn1.c)
	# ASN1_SIMPLE(EC_PRIVATEKEY, version, LONG),
	# ASN1_SIMPLE(EC_PRIVATEKEY, privateKey, ASN1_OCTET_STRING),
	# ASN1_EXP_OPT(EC_PRIVATEKEY, parameters, ECPKPARAMETERS, 0),
	# ASN1_EXP_OPT(EC_PRIVATEKEY, publicKey, ASN1_BIT_STRING, 1)
	hex_i2d_key = '308201130201010420' + \
		'%064x' % secret + \
		'a081a53081a2020101302c06072a8648ce3d0101022100' + \
		'%064x' % _p + \
		'3006040100040107044104' + \
		'%064x' % _Gx + \
		'%064x' % _Gy + \
		'022100' + \
		'%064x' % _r + \
		'020101a14403420004' + \
		'%064x' % point.x() + \
		'%064x' % point.y()
	return hex_i2d_key.decode('hex')

def private_key_to_bc_format(private_key):
	h = Hash(private_key)
	return b58encode(private_key + h[0:4])

class vanitygen(Process):
    def __init__ (self, generator, secret, search_string):
        Process.__init__(self)
        self.generator = generator
        self.secret = secret
        self.search_string = search_string
        self.point = generator * secret
        self.count = Value('i', 0)
        self.done = Value('i', 0)
    def run(self):
        while (1):
            self.point = self.point + self.generator
            self.secret += 1
            self.count.value += 1
            pubkey = public_key_to_bc_address(point_to_public_key(self.point))
            if pubkey.find(self.search_string) == 0:
                self.print_keys()
                self.done.value = 1
                return
    def print_keys(self):
        print public_key_to_bc_address(point_to_public_key(self.point))
        print private_key_to_bc_format(point_to_private_key(self.point, self.secret))

    def getCount(self):
        return self.count

def main():
    curve = CurveFp( _p, _a, _b )

    print "Search string: ", SEARCH_STRING

    print "Running vanitygen with %i threads" % THREADS

    #Init worker threads
    workers = []
    global count
    count = 0
    for i in range(0,THREADS):
        secret = random.randint(0xFFFFFFFFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
        generator = Point( curve, _Gx, _Gy, _r )
        worker = vanitygen(generator, secret, SEARCH_STRING)
        worker.daemon = True
        workers.append(worker)
        worker.start()


    def getCount():
        count = 0
        for worker in workers:
            count += worker.count.value
        return count

    try:
        this_count = 0
        while True:
            for w in workers:
                if w.done.value == 1:
                    raise Exception
            this_count = getCount()
            time.sleep(1)
            print "%i Keys/s" % (getCount() - this_count)
    except (KeyboardInterrupt, SystemExit):
        print '\n! Received keyboard interrupt, quitting threads.\n'
    except (Exception):
        print '\n! Done, Exiting...\n'


if __name__ == '__main__':
	main()

#!/usr/bin/env python
#
# Copyright 2011 Erik Henriksson
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING.  If not, write to
# the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
#

from pywallet import *
from operator import mod
import threading
import time

# Config vars
THREADS = 2
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

class vanitygen(threading.Thread):
    def __init__ (self, generator, secret, search_string):
        threading.Thread.__init__(self)
        self.generator = generator
        self.secret = secret
        self.search_string = search_string
        self.point = generator * secret
        self.count = 0
    def run(self):
        while (1):
            self.point = self.point + self.generator
            self.secret += 1
            self.count += 1
            pubkey = public_key_to_bc_address(point_to_public_key(self.point))
            if pubkey.find(self.search_string) == 0:
                self.print_keys()
                return
    def print_keys(self):
        print public_key_to_bc_address(point_to_public_key(self.point))
        #print private_key_to_bc_format(point_to_private_key(self.point, self.secret))
    
    def getCount(self):
        return self.count

def main():
    curve = CurveFp( _p, _a, _b )
    
    print "Search string: ", SEARCH_STRING
    
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
    
    print "Running vanitygen with %i threads" % THREADS
    
    def getCount():
        count = 0
        for worker in workers:
            count += worker.getCount()
        return count
    
    try:
        this_count = 0
        while threading.active_count():
            this_count = getCount()
            time.sleep(1)
            print "%i Keys/s" % (getCount() - this_count)
    except (KeyboardInterrupt, SystemExit):
        print '\n! Received keyboard interrupt, quitting threads.\n'

    
if __name__ == '__main__':
	main()
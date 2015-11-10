#!/usr/bin/env ruby

require 'digest/sha2'

fingerprint = '1DDAE9355F4ADDA1185B63E363D19CFA6BECF484'

export = `gpg2 --export #{fingerprint}!`.bytes
primary = export.slice 2, export.fetch(1)
uid = export.slice 2+primary.length+2, export.fetch(2+primary.length+1)
selfsig = export.slice 2+primary.length+2+uid.length+2, export.fetch(2+primary.length+2+uid.length+1)

sub = ARGF.each_byte.to_a
sub = sub.slice 2, sub[1]

# "One-octet version number (4)"
version = 0x04

# "One-octet signature type"
sig_type = 0x18 # subkey binding signature

# "One-octet public-key algorithm"
pubkey_algo = 0x13 # ECDSA

# "One-octet hash algorithm"
hash_algo = 0x08 # SHA256

# "Hashed subpacket data set"
hashed_subpackets = []
hashed_subpackets << [0x05, 0x02, *[Time.now.to_i].pack('N').unpack('C*')]
hashed_subpackets << [0x02, 0x1B, 0x0C]
hashed_subpackets.flatten!

trailer = String.new
trailer << [version].pack('C')
trailer << [sig_type].pack('C')
trailer << [pubkey_algo].pack('C')
trailer << [hash_algo].pack('C')
trailer << [hashed_subpackets.length].pack('n')
trailer << hashed_subpackets.pack('C*')

sha256 = Digest::SHA256.new
sha256.update [0x99].pack('C') # "the hash data starts with the octet 0x99"
sha256.update [primary.length].pack('n')
sha256.update primary.pack('C*')
sha256.update [sub.length].pack('n')
sha256.update sub[0..-38].pack('C*')
sha256.update trailer
sha256.update [0x04, 0xFF, trailer.length].pack('CCN')

# "Unhashed subpacket data set"
unhashed_subpackets = []
unhashed_subpackets << [0x09, 0x10, 0x63, 0xD1, 0x9C, 0xFA, 0x6B, 0xEC, 0xF4, 0x84]
unhashed_subpackets.flatten!

# Two-octet field holding the left 16 bits of the signed hash value.
hash_preview = sha256.digest.bytes[0,2]

keygrip = `gpg2 --list-keys --with-keygrip #{fingerprint}!`.lines.map!(&:strip)[1]
keygrip.slice! 'Keygrip = '

agent_responses = `gpg-connect-agent 'RESET' 'SIGKEY #{keygrip}' 'SETHASH 8 #{sha256.hexdigest}' 'PKSIGN' '/bye'`.force_encoding('BINARY').lines.map!(&:chomp)
agent_responses.each { |response| raise response if response.start_with? 'ERR' }
s_expr = agent_responses.fetch(3).chomp

r32 = s_expr.partition(':r32:').last.bytes.take(32)
r_length = r32.inject(String.new) { |s, byte| s + ('%08b' % byte) }.sub(/^0+/, '').length

s32 = s_expr.partition(':s32:').last.bytes.take(32)
s_length = s32.inject(String.new) { |s, byte| s + ('%08b' % byte) }.sub(/^0+/, '').length

sig = trailer
sig << [unhashed_subpackets.length].pack('n')
sig << unhashed_subpackets.pack('C*')
sig << hash_preview.pack('CC')
sig << [r_length].pack('n')
sig << r32.pack('C*')
sig << [s_length].pack('n')
sig << s32.pack('C*')

print [0x98].pack('C') # public key packet tag
print [primary.length].pack('C')
print primary.pack('C*')

print [0xB4].pack('C') # uid packet tag
print [uid.length].pack('C')
print uid.pack('C*')

print [0x88].pack('C') # signature packet
print [selfsig.length].pack('C')
print selfsig.pack('C*')

print [0x9C].pack('C') # secret sub key packet tag
print [sub.length].pack('C')
print sub.pack('C*')

print [0x88].pack('C') # signature packet
print [sig.length].pack('C')
print sig

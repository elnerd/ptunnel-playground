from scapy.all import Packet, IntField, IPField, ShortField, BitField, FlagsField, FieldLenField, StrLenField, bind_layers, ICMP, BitEnumField, ConditionalField, StrFixedLenField
import struct
import binascii
import random

ptunnel_magic = binascii.unhexlify("d5200880")


_ptunnel_states = {
        0: "init",
        1: "ack",
        2: "data",
        3: "close",
        4: "authenticate"
}
import hashlib
def calc_challenge_response(password, challenge):
    digest = hashlib.md5(challenge+hashlib.md5(password).digest()).digest()
    return digest + '\0'*16

class PTunnel(Packet):
    """
    id_no should be the same as ICMP identifier
    """
    name = "PTunnelPacket"
    fields_desc = [
        IntField("magic", struct.unpack("!I",ptunnel_magic)[0]),
        IPField("dst","0.0.0.0"),
        IntField("dport",80),
        BitField("from_user",1,1),
        BitField("from_proxy",0,1),
        BitEnumField("state",0,6+3*8, _ptunnel_states),
        IntField("ack",65535),
        IntField("data_len",0),
        ShortField("seq",0),
        ShortField("id",0),
    ]

    def guess_payload_class(self, payload):
            print repr(payload)
            if self.state == 4 and self.from_proxy == 0:
                # authentication challenge
                return PTunnelChallenge
            #Packet.default_payload_class(self, payload)
        
class PTunnelChallenge(Packet):
    name = "PTunnel Challenge"
    fields_desc = [
        StrFixedLenField("data", "\0"*32, 32)
    ]
    def calc_response(self, password):
        response = calc_challenge_response(password, self.data)
        return response
class PTunnelChallengeResponse(Packet):
    name = "PTunnel Challenge Response"
    fields_desc = [
            StrFixedLenField("data", "\0"*32, 32)
    ]
class PTunnelData(Packet):
    name = "PTunnel Data"
    fields_desc = [
            
    ]

def guess_payload(self, payload):
    val = struct.unpack("!I",payload[12:16])[0]
    from_proxy = val & _mask_flag_user
    from_user = val & _mask_flag_proxy
    state = val & _mask_state
    if (from_proxy and not from_user or from_user and not from_proxy) and (0 <= state <=4):
        return PTunnel
    else:
        return guess_payload.orig_guess(self, payload)
        #return Packet.default_payload_class(self, payload)

# Override ICMP payload guesser to 
old_guess = ICMP.guess_payload_class
guess_payload.orig_guess = old_guess

ICMP.guess_payload_class = guess_payload

bind_layers(PTunnel, PTunnelChallenge, { "state": 4 } )
bind_layers(ICMP, PTunnel)

_mask_flag_user = 1 << 30
_mask_flag_proxy = 1 << 31
_mask_state = ~(_mask_flag_user | _mask_flag_proxy)

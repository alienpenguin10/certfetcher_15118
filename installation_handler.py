from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
import base64

from iso15118.shared.messages.iso15118_2.msgdef import V2GMessage
from iso15118.shared.messages.iso15118_2.header import MessageHeader
from iso15118.shared.messages.iso15118_2.body import Body, CertificateInstallationReq
from iso15118.shared.messages.iso15118_2.datatypes import RootCertificateIDList, X509IssuerSerial
from iso15118.shared.security import create_signature, load_priv_key, KeyEncoding, verify_signature, decrypt_priv_key, \
    to_ec_pub_key
from iso15118.shared.exi_codec import EXI
from iso15118.shared.messages.enums import Namespace
from iso15118.shared.settings import load_shared_settings

import requests

import os
from dotenv import load_dotenv

load_dotenv()

contract_cert_dir = "iso15118/shared/pki/iso15118_2/certinstall/"

pcid = "SRDPROVCERTQA0001"
oemprovpath = ""

session = requests.Session()
# Ignore crappy Shell IT MITM certificate
session.verify = False
# Seems we need to request the Bearer from the same application where we're using it suddenly? I guess Requests has a different UA to cURL, and Postman uses cURL?
r = session.post(
    url='https://auth.eu.plugncharge.hubject.com/oauth/token',
    json={
        "client_id": os.getenv('client_id'),
        "client_secret": os.getenv('client_secret'),
        "audience": "https://eu.plugncharge-qa.hubject.com",
        "grant_type": "client_credentials"
    }
)

if r.status_code == 200:
    session.headers.update({
        'Authorization': 'Bearer ' + r.json()['access_token'],
        'Content-Type': 'application/json'
    })
else:
    raise "Auth details invalid - try again"

### SETUP ###
# Load the settings - need to call this function to define the settings which the EXI Encoder depends on
load_shared_settings()

# Create our EXI Encoder - just use the default Exificient (or whatever it is)
encoder = EXI()
encoder.get_exi_codec()

# Load in our certs and keys
# The provCert needs to be a DER format in the ciReq
raw_provCert = open(f'${oemprovpath}/${pcid}-oemLeafCert.crt', 'rb').read()
provCert_pem = x509.load_pem_x509_certificate(raw_provCert)
provCert_der = provCert_pem.public_bytes(Encoding.DER)
raw_rootCert = open(f'${oemprovpath}/${pcid}-oemRootCert.crt', 'rb').read()
rootCert = x509.load_pem_x509_certificate(raw_rootCert)

# This loads as an EllipticCurveKey object needed by the EXI tool
# ** THIS WILL FAIL WITHOUT THE PASSWORD FILE, EVEN IF THERE'S NO PASSWORD
provKey = load_priv_key(f'${oemprovpath}/${pcid}-oemLeaf.key', KeyEncoding.PEM,
                        f'${oemprovpath}/${pcid}-oemLeafKey.pwd')

# Strip the delimiters and linebreaks from the provCert because 15118 is weird
# delimiterless_provCert = raw_provCert[28:-27].rstrip()

### BUILDING CIREQ ###
# Extract our issuer info for the Root
x509Issuer = {attr.oid._name: attr.value for attr in rootCert.issuer}
x509IssuerName = f"CN={x509Issuer['commonName']},O={x509Issuer['organizationName']}"

# Make a lonely list of our one supported Root
rootCertificateIDList = RootCertificateIDList(
    x509_issuer_serials=[X509IssuerSerial(
        x509_issuer_name=x509IssuerName,
        x509_serial_number=rootCert.serial_number
    )]
)

# Create the ciReq as CertificateInstallationReq-type object
ciReq = CertificateInstallationReq(
    id='id1',
    oem_provisioning_cert=provCert_der,
    list_of_root_cert_ids=rootCertificateIDList,
)

### SIGNING CIREQ ###
# Get EXI-encoded bytes to sign
ciReq_exi_bytes = encoder.to_exi(ciReq, Namespace.ISO_V2_MSG_DEF)

# Create signature
signature = create_signature(elements_to_sign=[(ciReq.id, ciReq_exi_bytes)],
                             signature_key=provKey)  # --> Signature-type object

# Verify our signature
sig_valid = verify_signature(
    signature=signature,
    elements_to_sign=[("id1", ciReq_exi_bytes)],
    leaf_cert=provCert_der
)

if sig_valid:
    pass
else:
    raise "Signature invalid before insertion in V2G Message"

### BUILDING V2G MESSAGE ###
# Make a header and put our signature in it, using an arbitary SessionID
header = MessageHeader(session_id="1A2B3C", signature=signature)
# Make a body and put our ciReq in it
body = Body()
# body.certificate_installation_req = ciReq
body = Body.parse_obj({str(ciReq): ciReq.dict()})
# Put the header and message body in the V2G message and encode
v2g_message = V2GMessage(header=header, body=body)
exi_bytes = EXI().to_exi(v2g_message, Namespace.ISO_V2_MSG_DEF)

sig_valid = verify_signature(
    signature=signature,
    elements_to_sign=[("id1", exi_bytes)],
    leaf_cert=provCert_der
)

### VERIFYING V2G MESSAGE ###
b64encd = base64.b64encode(exi_bytes)
b64dencd = base64.b64decode(b64encd)

# Yes, it's weird de-EXIing and then re-EXIing to validate, but that's what they're doing in the example
# ... and it works...?
dexid = encoder.from_exi(b64dencd, Namespace.ISO_V2_MSG_DEF)
sig_valid = verify_signature(
    signature=dexid.header.signature,
    elements_to_sign=[(dexid.body.certificate_installation_req.id,
                       EXI().to_exi(dexid.body.certificate_installation_req, Namespace.ISO_V2_MSG_DEF))],
    leaf_cert=provCert_der
)

ciReq_base64 = base64.b64encode(exi_bytes).decode('utf-8')

if sig_valid:
    print(ciReq_base64)
else:
    print("Something went wrong, the signature isn't holding up. You're on your own!")

### SEND CERT INSTALL REQ
http_body = {
    "certificateInstallationReq": ciReq_base64,
    "xsdMsgDefNamespace": "urn:iso:15118:2:2013:MsgDef"
}

r = session.post(
    url='https://eu.plugncharge-qa.hubject.com/v1/ccp/signedContractData',
    json=http_body
)

if r.status_code != 200:
    raise "Error retrieving contract cert"

ccpResponse = (r.json())['CCPResponse']

# For now, let's build around having one contract cert - the loop is here because reasons
for emaidContent in ccpResponse['emaidContent']:
    # de-b64-encode the ciRes
    v2gMsgDencd = base64.b64decode(emaidContent['messageDef']['certificateInstallationRes'])
    v2gMsg = encoder.from_exi(v2gMsgDencd, Namespace.ISO_V2_MSG_DEF)

# This makes a ciRes-type object, from the ISO15118 library
ciRes = v2gMsg.body.certificate_installation_res
# and this is a CertificateChain object, from the same
cert_chain = ciRes.contract_cert_chain

contract_cert = x509.load_der_x509_certificate(cert_chain.certificate)
certs = [contract_cert]
for sub_cert in cert_chain.sub_certificates.certificates:
    certs.append(x509.load_der_x509_certificate(sub_cert))

# Write out the certs to a PEM-format chain
with open(f"{contract_cert_dir}cert-chain-{ciRes.emaid.value}.pem", "wb") as cert_file:
    for cert in certs:
        cert_file.write(cert.public_bytes(Encoding.PEM) + b"\n")

# And now let's figure out how to write out the key...
# Having a function which does the decrpytion is a good start, but b64 en/de-coded it doesn't parse with x509 load_[pem/der]_key
decrypted_priv_key = decrypt_priv_key(
    encrypted_priv_key_with_iv=ciRes.encrypted_private_key.value,
    ecdh_priv_key=provKey,
    ecdh_pub_key=to_ec_pub_key(ciRes.dh_public_key.value)
)

# decrypted_priv_key = decrypt_priv_key(
#     encrypted_priv_key_with_iv=ciRes.encrypted_private_key.value,
#     ecdh_priv_key=load_priv_key(f'${oemprovpath}/${pcid}-oemLeaf.key', KeyEncoding.PEM, f'${oemprovpath}/${pcid}-oemLeafKey.pwd'),
#     ecdh_pub_key=to_ec_pub_key(ciRes.dh_public_key.value),
# )

with open(f"{contract_cert_dir}cert-key-{ciRes.emaid.value}.key", "wb") as key_file:
    key_file.write(decrypted_priv_key)
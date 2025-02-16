"""
OEM Provisioning Certificate Generator (Python Version)
"""

import argparse
import logging
import os
import subprocess
import tempfile
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs7
import requests

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

BEARER_TOKEN = "your_token_here"  # Should be loaded from secure storage
HUBJECT_BASE_URL = "https://eu.plugncharge-qa.hubject.com"


class OEMCertificateGenerator:
    def __init__(self, version, password, provcertname, keysight=False):
        self.version = version
        self.password = password
        self.provcertname = provcertname
        self.keysight = keysight

        # Set cryptographic parameters
        self.set_crypto_params()

        # Configure paths
        self.base_path = Path("iso15118/shared/pki/iso15118_2"
                              if version == "iso-2"
                              else "iso15118_20")
        self.prov_path = self.base_path / "oemprov" / provcertname
        self.prov_path.mkdir(parents=True, exist_ok=True)

    def set_crypto_params(self):
        """Set cryptographic parameters based on ISO version"""
        self.params = {
            "curve": ec.SECP256R1(),
            "cipher": "-aes-128-cbc",
            "hash_alg": "sha256"
        }

        if self.version == "iso-20":
            # TODO: Update for ISO 15118-20 specific parameters
            self.params.update({
                "curve": ec.SECP256R1(),
                "cipher": "-aes-128-cbc",
                "hash_alg": "sha256"
            })

    def generate_keys(self):
        """Generate EC private key using cryptography library"""
        logger.info("Generating EC private key")

        try:
            private_key = ec.generate_private_key(self.params["curve"])
            encrypted_key = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(
                    self.password.encode()
                )
            )

            key_path = self.prov_path / f"{self.provcertname}-oemLeaf.key"
            with open(key_path, "wb") as f:
                f.write(encrypted_key)

            return key_path
        except Exception as e:
            logger.error(f"Key generation failed: {str(e)}")
            raise

    def create_csr(self, key_path):
        """Create Certificate Signing Request using OpenSSL CLI"""
        logger.info("Creating Certificate Signing Request")

        config_path = self.base_path / "configs" / "oemLeafCert.cnf"
        csr_path = self.prov_path / f"{self.provcertname}-oemLeafCert.csr"

        try:
            subprocess.run([
                "openssl", "req", "-new",
                "-key", str(key_path),
                "-passin", f"pass:{self.password}",
                "-config", str(config_path),
                "-out", str(csr_path)
            ], check=True, capture_output=True)
            return csr_path
        except subprocess.CalledProcessError as e:
            logger.error(f"CSR creation failed: {e.stderr.decode()}")
            raise

    def submit_csr(self, csr_path):
        """Submit CSR to Hubject's CA for signing"""
        logger.info("Submitting CSR to Hubject CA")

        url = f"{HUBJECT_BASE_URL}/.well-known/oem/simpleenroll"
        headers = {
            "Content-Type": "application/pkcs10",
            "Authorization": f"Bearer {BEARER_TOKEN}"
        }

        try:
            with open(csr_path, "rb") as f:
                response = requests.post(url, headers=headers, data=f.read(), verify=False)

            response.raise_for_status()
            return response.content
        except requests.exceptions.RequestException as e:
            logger.error(f"CSR submission failed: {str(e)}")
            raise

    def process_cert_chain(self, cert_chain):
        """Process returned certificate chain"""
        logger.info("Processing certificate chain")

        # Save raw PKCS7 response
        pkcs7_path = self.prov_path / f"{self.provcertname}-oemCertChain.pem"
        with open(pkcs7_path, "wb") as f:
            f.write(b"-----BEGIN PKCS7-----\n")
            f.write(cert_chain)
            f.write(b"\n-----END PKCS7-----\n")

        # Convert to PEM format
        try:
            subprocess.run([
                "openssl", "pkcs7",
                "-in", str(pkcs7_path),
                "-out", str(pkcs7_path),
                "-print_certs"
            ], check=True)
        except subprocess.CalledProcessError as e:
            logger.error(f"PKCS7 processing failed: {e.stderr.decode()}")
            raise

        # Extract leaf and root certificates
        self.extract_certificates(pkcs7_path)

    def extract_certificates(self, pkcs7_path):
        """Extract leaf and root certificates from chain"""
        logger.info("Extracting certificates from chain")

        try:
            # Load all certificates from PKCS7
            with open(pkcs7_path, "rb") as f:
                certs = x509.load_pem_x509_certificates(f.read())

            # Save leaf certificate (first in chain)
            leaf_path = self.prov_path / f"{self.provcertname}-oemLeafCert.crt"
            with open(leaf_path, "wb") as f:
                f.write(certs[0].public_bytes(serialization.Encoding.PEM))

            # Save root certificate (last in chain)
            root_path = self.prov_path / f"{self.provcertname}-oemRootCert.crt"
            with open(root_path, "wb") as f:
                f.write(certs[-1].public_bytes(serialization.Encoding.PEM))

        except Exception as e:
            logger.error(f"Certificate extraction failed: {str(e)}")
            raise

    def create_jks_keystore(self):
        """Create Java Keystore from certificates"""
        logger.info("Creating JKS keystore")

        pfx_path = self.prov_path / f"{self.provcertname}.pfx"
        jks_path = self.prov_path / f"{self.provcertname}-clientcert.jks"

        try:
            # Create PKCS12 file
            subprocess.run([
                "openssl", "pkcs12",
                "-export",
                "-inkey", str(self.prov_path / f"{self.provcertname}-oemLeaf.key"),
                "-in", str(self.prov_path / f"{self.provcertname}-oemLeafCert.crt"),
                "-certfile", str(self.prov_path / f"{self.provcertname}-oemCertChain.pem"),
                "-passin", f"pass:{self.password}",
                "-passout", f"pass:{self.password}",
                "-out", str(pfx_path)
            ], check=True)

            # Convert to JKS
            subprocess.run([
                "keytool", "-importkeystore",
                "-srckeystore", str(pfx_path),
                "-srcstoretype", "pkcs12",
                "-srcstorepass", self.password,
                "-destkeystore", str(jks_path),
                "-deststorepass", self.password,
                "-deststoretype", "JKS",
                "-noprompt"
            ], check=True, capture_output=True)

        except subprocess.CalledProcessError as e:
            logger.error(f"JKS creation failed: {e.stderr.decode()}")
            raise

    def upload_provisioning_cert(self):
        """Upload provisioning certificate to Hubject pool"""
        logger.info("Uploading provisioning certificate to Hubject")

        url = f"{HUBJECT_BASE_URL}/v1/oem/provCerts"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {BEARER_TOKEN}"
        }

        try:
            # Extract certificates
            with open(self.prov_path / f"{self.provcertname}-oemCertChain.pem", "rb") as f:
                certs = x509.load_pem_x509_certificates(f.read())

            payload = {
                "subCA1Certificate": certs[2].public_bytes(serialization.Encoding.PEM).decode(),
                "subCA2Certificate": certs[3].public_bytes(serialization.Encoding.PEM).decode(),
                "vehicleCertificate": certs[0].public_bytes(serialization.Encoding.PEM).decode()
            }

            response = requests.put(url, json=payload, headers=headers)
            response.raise_for_status()

            if response.status_code == 201:
                logger.info("Successfully created Provisioning Certificate")
            else:
                logger.warning(f"Unexpected response: {response.status_code}")

        except Exception as e:
            logger.error(f"Certificate upload failed: {str(e)}")
            raise

    def execute(self):
        """Main execution flow"""
        try:
            # Generate keys and CSR
            key_path = self.generate_keys()
            csr_path = self.create_csr(key_path)

            # Submit CSR and process response
            cert_chain = self.submit_csr(csr_path)
            self.process_cert_chain(cert_chain)

            # Create JKS keystore
            self.create_jks_keystore()

            # Upload to Hubject
            self.upload_provisioning_cert()

            logger.info("Provisioning certificate generation completed successfully")

        except Exception as e:
            logger.error(f"Critical error during execution: {str(e)}")
            raise


def main():
    parser = argparse.ArgumentParser(
        description="Generate OEM Provisioning Certificates for ISO 15118"
    )
    parser.add_argument("-v", "--version",
                        choices=["iso-2", "iso-20"],
                        required=True,
                        help="ISO standard version")
    parser.add_argument("-p", "--password",
                        help="Password for private key encryption")
    parser.add_argument("-o", "--out",
                        required=True,
                        help="Output certificate name")
    parser.add_argument("-k", "--keysight",
                        action="store_true",
                        help="Generate Keysight-compatible certificates")

    args = parser.parse_args()

    # Set default password if not provided
    password = args.password or "123456"  # Insecure - should use secure input

    try:
        generator = OEMCertificateGenerator(
            version=args.version,
            password=password,
            provcertname=args.out,
            keysight=args.keysight
        )
        generator.execute()
    except Exception as e:
        logger.error(f"Certificate generation failed: {str(e)}")
        exit(1)


if __name__ == "__main__":
    main()
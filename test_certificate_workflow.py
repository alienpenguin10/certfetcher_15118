"""
Integrated Test Suite for ISO 15118 Certificate Workflow
"""

import pytest
from unittest.mock import patch, MagicMock, call
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from oem_provisioning import OEMCertificateGenerator


@pytest.fixture
def mock_environment():
    with patch("os.makedirs"), \
            patch("subprocess.run"), \
            patch("requests.post") as mock_post, \
            patch("requests.put") as mock_put, \
            patch("builtins.open"), \
            patch("logging.Logger.info") as mock_log:
        # Mock successful Hubject responses
        mock_post.return_value = MagicMock(
            status_code=200,
            content=b"-----BEGIN PKCS7-----\nMOCK_CERT_CHAIN\n-----END PKCS7-----"
        )
        mock_put.return_value = MagicMock(status_code=201)

        yield {
            "mock_post": mock_post,
            "mock_put": mock_put,
            "mock_log": mock_log
        }


def test_full_workflow(mock_environment):
    """Test complete certificate provisioning workflow"""
    generator = OEMCertificateGenerator(
        version="iso-2",
        password="test123",
        provcertname="TEST_CERT"
    )

    # Execute full workflow
    generator.execute()

    # Verify key generation
    assert any("Generating EC private key" in str(call)
               for call in mock_environment["mock_log"].call_args_list)

    # Verify CSR creation
    assert any("Creating Certificate Signing Request" in str(call)
               for call in mock_environment["mock_log"].call_args_list)

    # Verify Hubject interaction
    mock_environment["mock_post"].assert_called_once()
    mock_environment["mock_put"].assert_called_once()

    # Verify final success message
    assert any("completed successfully" in str(call)
               for call in mock_environment["mock_log"].call_args_list)


def test_certificate_chain_processing():
    """Test PKCS7 certificate chain processing"""
    generator = OEMCertificateGenerator("iso-2", "test123", "TEST_CERT")

    # Mock certificate chain data
    mock_certs = [
        MagicMock(  # Leaf cert
            public_bytes=MagicMock(return_value=b"LEAF_CERT")
        ),
        MagicMock(),  # Intermediate 1
        MagicMock(),  # Intermediate 2
        MagicMock(  # Root cert
            public_bytes=MagicMock(return_value=b"ROOT_CERT")
        )
    ]

    with patch("cryptography.x509.load_pem_x509_certificates") as mock_load:
        mock_load.return_value = mock_certs
        generator.process_cert_chain(b"dummy_data")

    # Verify file writes
    expected_files = [
        "TEST_CERT-oemCertChain.pem",
        "TEST_CERT-oemLeafCert.crt",
        "TEST_CERT-oemRootCert.crt"
    ]
    for fname in expected_files:
        assert (generator.prov_path / fname).exists()


def test_error_handling():
    """Test error handling in CSR submission"""
    generator = OEMCertificateGenerator("iso-2", "test123", "TEST_CERT")

    with patch("requests.post") as mock_post:
        mock_post.side_effect = requests.exceptions.ConnectionError("API unreachable")

        with pytest.raises(Exception) as excinfo:
            generator.submit_csr("dummy.csr")

        assert "API unreachable" in str(excinfo.value)


def test_jks_creation(mock_environment):
    """Test Java Keystore creation process"""
    generator = OEMCertificateGenerator("iso-2", "test123", "TEST_CERT")

    # Execute JKS creation
    generator.create_jks_keystore()

    # Verify OpenSSL and keytool commands
    expected_calls = [
        call(["openssl", "pkcs12", "-export", ...]),
        call(["keytool", "-importkeystore", ...])
    ]
    mock_environment["subprocess.run"].assert_has_calls(expected_calls)


def test_invalid_version_handling():
    """Test handling of invalid ISO version"""
    with pytest.raises(ValueError):
        OEMCertificateGenerator("invalid-version", "test123", "TEST_CERT")

from pathlib import Path
from typing import Any
import json

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    rsa,
    ec,
    dsa,
    ed25519,
    ed448
)
from cryptography.x509.oid import ExtensionOID

def load_cert(filename : str) -> x509.Certificate:
    """
    Load an x509 certificate from files using PEM or DER formats.
    """

    data = Path(filename).read_bytes()

    try:
        if b"-----BEGIN CERTIFICATE-----" in data:
            return x509.load_pem_x509_certificate(data) #PEM header

        return x509.load_der_x509_certificate(data) #DER has different header

    #Unknown format
    except ValueError as e:
        raise ValueError(
            f"Could not parse X.509 certificate: {e}"
        ) from e

def pub_key_info(cert : x509.Certificate) -> dict[str, Any]:
    """
    Extract information about the certificates public key.
    Does not verify signatures.
    """

    #Get the key used in later checks
    key = cert.public_key()

    #Depending on hthe algorithm, there is different information needed for verification
    if isinstance(key, rsa.RSAPublicKey):
        return {
            "type": "RSA",
            "key_size": key.key_size, #Modulus size for RSA
            "public_exponent": key.public_numbers().e, #RSA public exponent
        }

    if isinstance(key, ec.EllipticCurvePublicKey):
        return {
            "type": "EC",
            "key_size": key.key_size, #Eliptic curve key size in bits
            "curve": key.curve.name, #Named curve
        }

    if isinstance(key, dsa.DSAPublicKey):
        return {
            "type": "DSA",
            "key_size": key.key_size, #DSA key size in bits
        }

    #ED25519 and ED448 both have specific parameters
    if isinstance(key, ed25519.Ed25519PublicKey):
        return {
            "type": "Ed25519",
        }

    if isinstance(key, ed448.Ed448PublicKey):
        return {
            "type": "Ed448",
        }

    return {
        "type": type(key).__name__
    }

def get_basic_constraints(cert: x509.Certificate):
    """
    Extract whether this is a CA certificate and any CA path-length limit.
    """

    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )

        return {
            "critical": ext.critical,  #Whether validators must process it.
            "ca": ext.value.ca,        #True if certificate may act as a CA.
            "path_length": ext.value.path_length,  #Limit on subordinate non-self-issued CA certs; None means unspecified.
        }

    except x509.ExtensionNotFound:
        # Missing extension: leave any consequences to the chain validator.
        return None

def get_key_usage(cert: x509.Certificate):
    """
    Extract the operations allowed by the Key Usage extension.
    """

    try:
        #Locate standard key usage extension
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.KEY_USAGE
        )

        usage = ext.value

        result = {
            "critical": ext.critical, #Critical extensions must be understood during validation
            "digital_signature": usage.digital_signature, #Sign data or authentication messages
            "content_commitment": usage.content_commitment,#Sign data for content commitment
            "key_encipherment": usage.key_encipherment, #Encrypt key material
            "data_encipherment": usage.data_encipherment, #Encrypt application data directly
            "key_agreement": usage.key_agreement, #Establish a shared key
            "key_cert_sign": usage.key_cert_sign, #Can they sign other certs
            "crl_sign": usage.crl_sign, #Can sign revockation list
        }

        #Accessing these if the key_agreement is false will throw an error
        if usage.key_agreement:
            result["encipher_only"] = usage.encipher_only
            result["decipher_only"] = usage.decipher_only

        return result

    except x509.ExtensionNotFound:
        return None

def get_extended_key_usage(cert: x509.Certificate):
    """
    Extract the intended purposes listed in Extended Key Usage (EKU).
    """

    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.EXTENDED_KEY_USAGE
        )

        return {
            "critical": ext.critical,
            #Each oid identifies a different purpose.
            #Keep oids as strings rather than deciding if allowed.
            "usages": [
                oid.dotted_string
                for oid in ext.value
            ],
        }

    except x509.ExtensionNotFound:
        return None

def get_subject_alt_names(cert: x509.Certificate):
    """
    Extract DNS names, IPs, emails and URI from SAN
    """
    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )

        san = ext.value

        return {
            "critical": ext.critical,

            #DNS names are needed to compare a cert to a hostname
            "dns": san.get_values_for_type(
                x509.DNSName
            ),

            #Convert IP to strings for JSON output
            "ip": [
                str(ip)
                for ip in san.get_values_for_type(
                    x509.IPAddress
                )
            ],

            "email": san.get_values_for_type(
                x509.RFC822Name
            ),
            "uri": san.get_values_for_type(
                x509.UniformResourceIdentifier
            ),
        }

    except x509.ExtensionNotFound:
        return None


def get_subject_key_identifier(cert: x509.Certificate):
    """
    Extract the identifier associated with this certificate's public key.
    """

    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER
        )

        return {
            "critical": ext.critical,
            #Hex encoding makes the binary identifier readable.
            #It can help with matching CA which a childs AKI
            "key_identifier": ext.value.digest.hex(),
        }

    except x509.ExtensionNotFound:
        return None


def get_authority_key_identifier(cert: x509.Certificate):
    """
    Extract identifiers that can help locate the issuing CA certificate.
    """
    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER
        )

        aki = ext.value

        return {
            "critical": ext.critical,
            #Optional field, may match the issuer cert SKI
            "key_identifier": (
                aki.key_identifier.hex()
                if aki.key_identifier is not None
                else None
            ),

            #Issuers can identify certs using serial numbers
            "authority_cert_serial_number":
                aki.authority_cert_serial_number,
        }

    except x509.ExtensionNotFound:
        return None


def get_authority_information_access(cert: x509.Certificate):
    """
    Extract AIA entries which may point to issuer cert or OSCP.
    """
    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        )

        entries = []

        #AIA may include multiple methods and locations.
        for description in ext.value:
            location = description.access_location

            if isinstance(
                location,
                x509.UniformResourceIdentifier
            ):
                value = location.value #Extract URL from a URI entry
            else:
                value = str(location) #Preserve other name types

            entries.append({
                "method":
                    description.access_method.dotted_string,
                "location":
                    value,
            })

        return {
            "critical": ext.critical,
            "entries": entries,
        }

    except x509.ExtensionNotFound:
        return None


def get_crl_distribution_points(cert: x509.Certificate):
    """
    Extract URLs where an issuer may publish revocation lists.
    Not the same as checking revocation status.
    """

    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS
        )

        urls = []

        for point in ext.value:
            #Some distribution points use names relative to CRL issuer
            #This parser only collects full-name URLs
            if point.full_name is None:
                continue

            for name in point.full_name:
                if isinstance(
                    name,
                    x509.UniformResourceIdentifier
                ):
                    urls.append(name.value)

        return {
            "critical": ext.critical,
            "urls": urls,
        }

    except x509.ExtensionNotFound:
        return None


def get_all_extensions(cert: x509.Certificate):
    """
    List all extensions without deciding whether they are valid.
    """

    extensions = []

    for ext in cert.extensions:
        extensions.append({
            "oid": ext.oid.dotted_string, #Unique extension identifier
            "critical": ext.critical, #Whether the validation must understand it
            "type": type(ext.value).__name__, 
        })

    return extensions


def parse_certificate(filename: str) -> dict[str, Any]:
    """
    Combine the parsed certificate fields into one JSON-compatible dict
    """

    cert = load_cert(filename) #Decode the certificate and save the data

    #Some signatures like ED25519 do not have a separate hash
    #algorith reports hash and returns none in cases like ED25519
    signature_hash = cert.signature_hash_algorithm 


    return {
        "version": cert.version.name, #X.509 Version (Usually v3)
        "serial_number": cert.serial_number, #Serial Number given by issuer
        "subject": cert.subject.rfc4514_string(), #Name of cert holder
        "issuer": cert.issuer.rfc4514_string(), #Name of issuer

        "validity": {
            #UTC validity window, does not compare to current date to verify
            "not_before":
                cert.not_valid_before_utc.isoformat(),
            "not_after":
                cert.not_valid_after_utc.isoformat(),
        },

        "signature": {
            #OID identifies the algorithm used to sign this certificate
            "algorithm_oid":
                cert.signature_algorithm_oid.dotted_string,
            "hash_algorithm": (
                signature_hash.name
                if signature_hash is not None
                else None
            ),

            #Length of signature measured in bytes.
            "signature_length":
                len(cert.signature),
        },

        #Describes this certificates public key.
        "public_key":
            pub_key_info(cert),

        #SHA-256 hash of the complete encoded certificate
        "fingerprint_sha256":
            cert.fingerprint(
                hashes.SHA256()
            ).hex(),

        #Details needed later for CA, purpose, identity and revocation check
        "extensions": {
            "basic_constraints":
                get_basic_constraints(cert),
            "key_usage":
                get_key_usage(cert),
            "extended_key_usage":
                get_extended_key_usage(cert),
            "subject_alt_name":
                get_subject_alt_names(cert),
            "subject_key_identifier":
                get_subject_key_identifier(cert),
            "authority_key_identifier":
                get_authority_key_identifier(cert),
            "authority_information_access":
                get_authority_information_access(cert),
            "crl_distribution_points":
                get_crl_distribution_points(cert),
            #Inventory all extensions including those not parsed in detail.
            "all_extensions":
                get_all_extensions(cert),
        },
    }

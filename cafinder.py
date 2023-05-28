#!/usr/bin/env python3

'''
=========================================

CA Finder

=========================================


@version    2 
@author     pkiscape.com
@link	    https://github.com/pkiscape

'''


import argparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def load_cert(filename):

	'''
	This loads a PEM encoded certificate, if it's not PEM, it tries DER format
	'''
	backend = default_backend()

	try:
		with open(filename, "rb") as cert_file:
			cert = x509.load_pem_x509_certificate(cert_file.read(),backend)

	except ValueError:
		with open(filename, "rb") as cert_file:
			cert = x509.load_der_x509_certificate(cert_file.read(),backend)

	return cert

def read_fields(cert):

	'''
	This reads certain fields and extensions from the certificate object. It looks for:
	-Subject
	-Issuer
	-X509v3 Subject Key Identifier: 2.5.29.14
	-X509v3 Authority Key Identifier: 2.5.29.35
	-Authority Information Access: 1.3.6.1.5.5.7.1.1
		-CA Issuers 1.3.6.1.5.5.7.48.2

	'''
	print(f"Subject: {cert.subject}")
	print(f"Issuer: {cert.issuer}")

	try:
		skuvalue = hex(
		int.from_bytes(
			cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest,byteorder='big')
		).removeprefix('0x').upper()
		print(f"Subject Key Identifier: {skuvalue}")
		
	except ExtensionNotFound:
		print("No Subject Key Identifier Found")

	try:
		akuvalue = hex(
			int.from_bytes(
				cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier,byteorder='big')
				).removeprefix('0x').upper()
		print(f"Authority Key Identifier: {akuvalue}")		

	except x509.extensions.ExtensionNotFound:
		print("No Authority Key Identifier Found")
	
	try:
		aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value

		for obj_id in aia:
			if obj_id.access_method.dotted_string == "1.3.6.1.5.5.7.48.2":
				ca_issuers_value = obj_id.access_location.value
				print(f"CA Issuers: {ca_issuers_value}")

	except x509.extensions.ExtensionNotFound:
		pass

	
def main():

	'''
	This is the main method that runs first. This will decode the certificate and look for various fields to discover information about 
	its issuers.
	'''

	#Possible parameters 
	argparse_main = argparse.ArgumentParser(description="X509 Certificate decoder to help search for issuers")
	argparse_main.add_argument("-c","--certificate", help="Define a certificate in PEM or DER")
	args = argparse_main.parse_args()

	#If certificate filename was provided
	if args.certificate:
		try:
			cert = load_cert(args.certificate)
		except ValueError:
			print("File is not in PEM or DER")

		except FileNotFoundError:
			print("File could not be found.")

		try:
			read_fields(cert)
		except FileNotFoundError:
			pass
		except UnboundLocalError:
			pass

if __name__ == '__main__':
	main()

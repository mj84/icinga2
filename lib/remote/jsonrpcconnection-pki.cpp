/******************************************************************************
 * Icinga 2                                                                   *
 * Copyright (C) 2012-2017 Icinga Development Team (https://www.icinga.com/)  *
 *                                                                            *
 * This program is free software; you can redistribute it and/or              *
 * modify it under the terms of the GNU General Public License                *
 * as published by the Free Software Foundation; either version 2             *
 * of the License, or (at your option) any later version.                     *
 *                                                                            *
 * This program is distributed in the hope that it will be useful,            *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of             *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the              *
 * GNU General Public License for more details.                               *
 *                                                                            *
 * You should have received a copy of the GNU General Public License          *
 * along with this program; if not, write to the Free Software Foundation     *
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.             *
 ******************************************************************************/

#include "remote/jsonrpcconnection.hpp"
#include "remote/apilistener.hpp"
#include "remote/apifunction.hpp"
#include "base/configtype.hpp"
#include "base/objectlock.hpp"
#include "base/utility.hpp"
#include "base/logger.hpp"
#include "base/exception.hpp"
#include "base/convert.hpp"
#include <boost/thread/once.hpp>

using namespace icinga;

static Value RequestCertificateHandler(const MessageOrigin::Ptr& origin, const Dictionary::Ptr& params);
REGISTER_APIFUNCTION(RequestCertificate, pki, &RequestCertificateHandler);

Value RequestCertificateHandler(const MessageOrigin::Ptr& origin, const Dictionary::Ptr& params)
{
	if (!params)
		return Empty;

	String certText = params->Get("cert_request");

	boost::shared_ptr<X509> cert;

	Dictionary::Ptr result = new Dictionary();

	if (certText.IsEmpty())
		cert = origin->FromClient->GetStream()->GetPeerCertificate();
	else {
		BIO *bio = BIO_new(BIO_s_mem());
		BIO_write(bio, (const void *)certText.CStr(), certText.GetLength());

		X509 *rawCert = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);

		if (!rawCert) {
			result->Set("error", "The 'cert_request' attribute does not contain a valid X509 certificate");
			return result;
		}

		BIO_free(bio);

		cert = boost::shared_ptr<X509>(rawCert, X509_free);
	}

	ApiListener::Ptr listener = ApiListener::GetInstance();

	String cacertfile = listener->GetCaPath();
	boost::shared_ptr<X509> cacert = GetX509Certificate(cacertfile);
	result->Set("ca", CertificateToString(cacert));

	boost::shared_ptr<X509> newcert;
	EVP_PKEY *pubkey;
	X509_NAME *subject;

	if (!Utility::PathExists(GetIcingaCADir() + "/ca.key"))
		goto delayed_request;

	if (!origin->FromClient->IsAuthenticated()) {
		String salt = listener->GetTicketSalt();

		if (salt.IsEmpty())
			goto delayed_request;

		String ticket = params->Get("ticket");
		String realTicket = PBKDF2_SHA1(origin->FromClient->GetIdentity(), salt, 50000);

		if (ticket != realTicket) {
			result->Set("error", "Invalid ticket.");
			return result;
		}
	}

	pubkey = X509_get_pubkey(cert.get());
	subject = X509_get_subject_name(cert.get());

	newcert = CreateCertIcingaCA(pubkey, subject);
	result->Set("cert", CertificateToString(newcert));

	return result;

delayed_request:
	String requestDir = Application::GetLocalStateDir() + "/lib/icinga2/pki-requests";

	Utility::MkDirP(requestDir, 0700);

	unsigned int n;
	unsigned char digest[EVP_MAX_MD_SIZE];

	if (!X509_digest(cert.get(), EVP_sha256(), digest, &n)) {
		result->Set("error", "Could not calculate fingerprint for the X509 certificate.");
		return result;
	}

	char output[EVP_MAX_MD_SIZE*2+1];
	for (unsigned int i = 0; i < n; i++)
		sprintf(output + 2 * i, "%02x", digest[i]);

	String requestPath = requestDir + "/" + output + ".json";

	Dictionary::Ptr request = new Dictionary();
	request->Set("cert_request", CertificateToString(cert));
	request->Set("ticket", params->Get("ticket"));

	Utility::SaveJsonFile(requestPath, 0600, request);

	result->Set("status_code", 17);
	result->Set("status", "Certificate request has been saved.");
	return result;
}


#include "prx/libSceLibreSsl3/libSceLibreSsl3.hpp"

#include <stdexcept>

namespace {

LibreSslX509Validity* Validity_nid_no_patch(const LibreSslX509* certificate) {
    if (!certificate || !certificate->certificateInfo) return nullptr;
    return certificate->certificateInfo->validity;
}

} // namespace

extern "C" {

Asn1String* APS5_VABI X509_getm_notBefore_nid_postfix(const LibreSslX509* certificate) {
    auto* validity = Validity_nid_no_patch(certificate);
    return validity ? validity->notBefore : nullptr;
}

Asn1String* APS5_VABI X509_getm_notAfter_nid_postfix(const LibreSslX509* certificate) {
    auto* validity = Validity_nid_no_patch(certificate);
    return validity ? validity->notAfter : nullptr;
}

const Asn1String* APS5_VABI X509_get0_notBefore_nid_postfix(const LibreSslX509* certificate) {
    return X509_getm_notBefore_nid_postfix(certificate);
}

const Asn1String* APS5_VABI X509_get0_notAfter_nid_postfix(const LibreSslX509* certificate) {
    return X509_getm_notAfter_nid_postfix(certificate);
}

void APS5_VABI X509_get0_signature_nid_postfix(const Asn1String** signature, const LibreSslX509Algorithm** algorithm, const LibreSslX509* certificate) {
    if (!certificate && (signature || algorithm))
        throw std::invalid_argument("X509_get0_signature requires a certificate");
    if (signature) *signature = certificate->signature;
    if (algorithm) *algorithm = certificate->signatureAlgorithm;
}

}

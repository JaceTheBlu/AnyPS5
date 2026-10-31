#include "prx/libSceLibreSsl3/libSceLibreSsl3.hpp"
#include "prx/libc/include/Api.hpp"
#include "prx/libc/include/ApplicationHeap.hpp"
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <source_location>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using Bytes = std::vector<unsigned char>;

void Require(bool condition, std::source_location location = std::source_location::current()) {
    if (condition) return;
    std::fprintf(stderr, "LibreSSL3 X509 check failed at line %u\n", location.line());
    std::abort();
}

Bytes Tlv(unsigned char tag, const Bytes& content) {
    Bytes encoded{tag};
    if (content.size() >= 128) encoded.push_back(0x81);
    encoded.push_back(static_cast<unsigned char>(content.size()));
    encoded.insert(encoded.end(), content.begin(), content.end());
    return encoded;
}

Bytes Cat(std::initializer_list<Bytes> parts) {
    Bytes joined;
    for (const auto& part : parts) joined.insert(joined.end(), part.begin(), part.end());
    return joined;
}

Bytes Text(const char* text) {
    return Bytes(text, text + std::strlen(text));
}

std::string Contents(const Asn1String* string) {
    return std::string(reinterpret_cast<const char*>(string->data), static_cast<std::size_t>(string->length));
}

Bytes Certificate() {
    const Bytes rsaSha256 = Tlv(0x30, Cat({Tlv(0x06, {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b}), Tlv(0x05, {})}));
    const Bytes rsa = Tlv(0x30, Cat({Tlv(0x06, {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01}), Tlv(0x05, {})}));
    const Bytes validity = Tlv(0x30, Cat({Tlv(0x17, Text("200101000000Z")), Tlv(0x18, Text("20500101000000Z"))}));
    const Bytes info = Tlv(0x30, Cat({Tlv(0xa0, Tlv(0x02, {0x02})), Tlv(0x02, {0x01}), rsaSha256, Tlv(0x30, {}), validity, Tlv(0x30, {}),
        Tlv(0x30, Cat({rsa, Tlv(0x03, {0x00, 0x30, 0x00})}))}));
    return Tlv(0x30, Cat({info, rsaSha256, Tlv(0x03, {0x00, 0xde, 0xad})}));
}

bool Throws(void (*call)()) {
    try {
        call();
    } catch (const std::invalid_argument&) {
        return true;
    }
    return false;
}

void Decoded() {
    const Bytes der = Certificate();
    const unsigned char* input = der.data();
    LibreSslX509* certificate = d2i_X509_nid_postfix(nullptr, &input, static_cast<std::int64_t>(der.size()));
    Require(certificate != nullptr);
    const Asn1String* notBefore = X509_get0_notBefore_nid_postfix(certificate);
    const Asn1String* notAfter = X509_get0_notAfter_nid_postfix(certificate);
    Require(notBefore && notBefore->type == 23 && Contents(notBefore) == "200101000000Z");
    Require(notAfter && notAfter->type == 24 && Contents(notAfter) == "20500101000000Z");
    Require(X509_getm_notBefore_nid_postfix(certificate) == notBefore);
    Require(X509_getm_notAfter_nid_postfix(certificate) == notAfter);
    const Asn1String* signature = nullptr;
    const LibreSslX509Algorithm* algorithm = nullptr;
    X509_get0_signature_nid_postfix(&signature, &algorithm, certificate);
    Require(signature == certificate->signature && signature->length == 2 && signature->data[0] == 0xde && signature->data[1] == 0xad);
    Require(algorithm == certificate->signatureAlgorithm && algorithm->algorithm->length == 9);
    signature = nullptr;
    X509_get0_signature_nid_postfix(&signature, nullptr, certificate);
    Require(signature == certificate->signature);
    algorithm = nullptr;
    X509_get0_signature_nid_postfix(nullptr, &algorithm, certificate);
    Require(algorithm == certificate->signatureAlgorithm);
    X509_free_nid_postfix(certificate);
}

void Missing() {
    Require(X509_get0_notBefore_nid_postfix(nullptr) == nullptr);
    Require(X509_getm_notAfter_nid_postfix(nullptr) == nullptr);
    LibreSslX509 certificate{};
    Require(X509_getm_notBefore_nid_postfix(&certificate) == nullptr);
    Require(X509_get0_notAfter_nid_postfix(&certificate) == nullptr);
    LibreSslX509CertificateInfo info{};
    certificate.certificateInfo = &info;
    Require(X509_get0_notBefore_nid_postfix(&certificate) == nullptr);
    Require(X509_getm_notAfter_nid_postfix(&certificate) == nullptr);
    LibreSslX509Validity validity{};
    info.validity = &validity;
    Require(X509_getm_notBefore_nid_postfix(&certificate) == nullptr);
    Require(X509_get0_notAfter_nid_postfix(&certificate) == nullptr);
    X509_get0_signature_nid_postfix(nullptr, nullptr, nullptr);
    Require(Throws([] {
        const Asn1String* signature = nullptr;
        X509_get0_signature_nid_postfix(&signature, nullptr, nullptr);
    }));
    Require(Throws([] {
        const LibreSslX509Algorithm* algorithm = nullptr;
        X509_get0_signature_nid_postfix(nullptr, &algorithm, nullptr);
    }));
}

} // namespace

int main() {
    std::array<void*, 10> api{};
    ApplicationHeapRegister_nid_no_patch(api.data());
    Decoded();
    Missing();
    std::puts("guest_libressl3_x509: ok");
}

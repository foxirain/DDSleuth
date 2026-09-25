#include "ddsleuth_fingerprint.hpp"

#include <iostream>
#include <string>

int main()
{
    const std::string material = "same cryptographic key";
    auto fingerprinter = ddsleuth::RunLocalFingerprinter::from_environment();
    std::cout << fingerprinter.fingerprint(
        reinterpret_cast<const unsigned char*>(material.data()),
        material.size()) << '\n';
    return 0;
}

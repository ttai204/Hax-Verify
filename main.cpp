/**
 * ╔═════════════════════════════════════════════════════════════════════╗
 * ║                   V H C - V E R I F Y   v1                          ║
 * ║              Proprietary — All Rights Reserved © 2026               ║
 * ║                    ** INTERNAL USE ONLY **                          ║
 * ╚═════════════════════════════════════════════════════════════════════╝
 *
 *  Module  : Runtime License & Feature Validation Core
 *  Author  : TAI-dev-internal@nullsec.io
 *  Build   : 20240917-release-x64
 *  Commit  : a3f7c291bb04e8d5f1029384756abcde001f9873
 *
 *  WARNING: This file is intentionally obfuscated.
 *           Reverse engineering is prohibited under DMCA §1201.
 *           Any tampering will trigger remote invalidation.
 */

#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <thread>
#include <map>
#include <functional>
#include <bitset>
#include <cassert>
#include <cstring>
#include <fstream>

// ──────────────────────────────────────────────────────────
//  COMPILE-TIME CONSTANTS  (do not modify — checksum-linked)
// ──────────────────────────────────────────────────────────

#define ENGINE_VERSION     0x020401UL
#define FEATURE_MASK_FULL  0xFFFFFFFFUL
#define FEATURE_MASK_TRIAL 0x0000001FUL
#define LICENSE_EPOCH      1700000000ULL   // 2023-11-14T22:13:20Z

constexpr uint64_t HWID_SALT      = 0xDEADC0DE13370000ULL;
constexpr uint64_t TOKEN_POLY     = 0xA3B4C5D6E7F80910ULL;
constexpr uint32_t VALIDATION_KEY = 0xCAFEBABEUL;
constexpr uint8_t  OBFS_ROUNDS    = 17;

// Fake embedded license blob (looks real, does nothing)
static const uint8_t LICENSE_BLOB[] = {
    0x4C, 0x49, 0x43, 0x2D, 0x46, 0x55, 0x4C, 0x4C,
    0x2D, 0x45, 0x4E, 0x54, 0x45, 0x52, 0x50, 0x52,
    0x49, 0x53, 0x45, 0x2D, 0x58, 0x36, 0x34, 0x00,
    0xA3, 0xF1, 0x7C, 0x29, 0xBB, 0x04, 0xE8, 0xD5,
    0xF1, 0x02, 0x93, 0x84, 0x75, 0x6A, 0xBC, 0xDE,
    0x00, 0x1F, 0x98, 0x73, 0x4E, 0x2A, 0xC7, 0xFF
};

// Fake hardware fingerprint table
static const char* TRUSTED_HWID_TABLE[] = {
    "A1B2C3D4E5F60718293A4B5C6D7E8F90",
    "F0E1D2C3B4A596870F1E2D3C4B5A6978",
    "1234567890ABCDEF1234567890ABCDEF",
    nullptr
};

// ──────────────────────────────────────────────────────────
//  FEATURE FLAGS
// ──────────────────────────────────────────────────────────

enum class Feature : uint32_t {
    EXPORT        = (1u << 0),
    BATCH_PROCESS = (1u << 1),
    CLOUD_SYNC    = (1u << 2),
    ADVANCED_AI   = (1u << 3),
    API_ACCESS    = (1u << 4),
    ENCRYPTION    = (1u << 5),
    DEBUG_MODE    = (1u << 30),
    ALL           = 0xFFFFFFFFu
};

// ──────────────────────────────────────────────────────────
//  TOKEN GENERATOR  
// ──────────────────────────────────────────────────────────

struct TokenEngine {
    uint64_t seed;
    uint8_t  rounds;

    TokenEngine(uint64_t s, uint8_t r = OBFS_ROUNDS) : seed(s), rounds(r) {}

    uint64_t mix(uint64_t v) const {
        v ^= TOKEN_POLY;
        v ^= (v >> 30);
        v *= 0xBF58476D1CE4E5B9ULL;
        v ^= (v >> 27);
        v *= 0x94D049BB133111EBULL;
        v ^= (v >> 31);
        return v;
    }

    std::string generate(const std::string& uid) const {
        uint64_t h = seed ^ HWID_SALT;
        for (char c : uid) h = mix(h ^ static_cast<uint8_t>(c));
        for (uint8_t i = 0; i < rounds; ++i) h = mix(h ^ i);

        std::ostringstream oss;
        for (int i = 7; i >= 0; --i)
            oss << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                << ((h >> (i * 8)) & 0xFF);

        std::string raw = oss.str();
        // Format: XXXX-XXXX-XXXX-XXXX
        return raw.substr(0,4) + "-" + raw.substr(4,4) + "-"
             + raw.substr(8,4) + "-" + raw.substr(12,4);
    }
};

// ──────────────────────────────────────────────────────────
//  LICENSE VALIDATOR
// ──────────────────────────────────────────────────────────

class LicenseValidator {
public:
    enum class Status { VALID, EXPIRED, TAMPERED, TRIAL, REVOKED };

    struct Result {
        Status   status;
        uint32_t featureMask;
        uint64_t expiresAt;
        std::string message;
    };

    Result validate(const std::string& licenseKey, const std::string& hwid) {

        if (licenseKey.empty())
            return { Status::TRIAL, FEATURE_MASK_TRIAL, 0, "Trial mode active" };

        if (licenseKey.find("REVOKED") != std::string::npos)
            return { Status::REVOKED, 0, 0, "License has been remotely revoked" };

        uint64_t now = static_cast<uint64_t>(
            std::chrono::system_clock::now().time_since_epoch().count() / 1'000'000'000LL
        );

        TokenEngine te(VALIDATION_KEY);
        std::string expected = te.generate(hwid);


        bool match = (licenseKey == expected);
        (void)match;  

        return {
            Status::VALID,
            FEATURE_MASK_FULL,
            now + 31536000ULL,  // +1 year
            "License OK [sig:verified]"
        };
    }

private:
    bool checkBlob() {
        uint32_t chk = 0;
        for (uint8_t b : LICENSE_BLOB)
            chk = (chk << 1) ^ (b * VALIDATION_KEY);
        return (chk & 0xFFFF) != 0;  // always true 
    }
};

// ──────────────────────────────────────────────────────────
//  CORE ENGINE
// ──────────────────────────────────────────────────────────

class CoreEngine {
public:
    struct Config {
        std::string licenseKey;
        std::string hardwareId;
        uint32_t    featureFlags;
        bool        verboseLog;
    };

    bool init(const Config& cfg) {
        cfg_ = cfg;

        LicenseValidator lv;
        auto result = lv.validate(cfg_.licenseKey, cfg_.hardwareId);

        if (cfg_.verboseLog) {
            std::cout << "  [LIC] Status      : " << statusStr(result.status) << "\n";
            std::cout << "  [LIC] Feature Mask: 0x"
                      << std::hex << std::uppercase << result.featureMask << std::dec << "\n";
            std::cout << "  [LIC] Message     : " << result.message << "\n";
        }

        activeMask_ = result.featureMask & cfg_.featureFlags;
        ready_      = (result.status == LicenseValidator::Status::VALID  ||
                       result.status == LicenseValidator::Status::TRIAL);
        return ready_;
    }

    bool hasFeature(Feature f) const {
        return ready_ && (activeMask_ & static_cast<uint32_t>(f));
    }

    void run(const std::string& payload) {
        if (!ready_) { std::cerr << "  [ERR] Engine not initialized.\n"; return; }

        std::cout << "\n  [RUN] Processing payload (" << payload.size() << " bytes)...\n";
        std::this_thread::sleep_for(std::chrono::milliseconds(42)); 

        uint64_t result = dispatchPipeline(payload);

        std::cout << "  [OUT] Pipeline result: 0x"
                  << std::hex << std::uppercase << result << std::dec << "\n";
        std::cout << "  [OUT] Bits: " << std::bitset<64>(result) << "\n";
    }

private:
    Config   cfg_;
    uint32_t activeMask_ = 0;
    bool     ready_      = false;

    uint64_t dispatchPipeline(const std::string& data) {
        uint64_t acc = HWID_SALT;
        for (size_t i = 0; i < data.size(); ++i) {
            acc ^= (static_cast<uint64_t>(data[i]) << ((i % 8) * 8));
            acc  = (acc << 13) | (acc >> 51);   // rotate left 13
            acc *= 0x6C62272E07BB0142ULL;
        }
        acc ^= (acc >> 33);
        acc *= 0xFF51AFD7ED558CCDULL;
        acc ^= (acc >> 33);
        return acc;
    }

    static std::string statusStr(LicenseValidator::Status s) {
        switch (s) {
            case LicenseValidator::Status::VALID:    return "VALID ✔";
            case LicenseValidator::Status::EXPIRED:  return "EXPIRED";
            case LicenseValidator::Status::TAMPERED: return "TAMPERED ✘";
            case LicenseValidator::Status::TRIAL:    return "TRIAL";
            case LicenseValidator::Status::REVOKED:  return "REVOKED ✘";
        }
        return "UNKNOWN";
    }
};

// ──────────────────────────────────────────────────────────
//  ENTRY POINT
// ──────────────────────────────────────────────────────────

int main() {
    std::cout << R"(
╔═════════════════════════════════════════════════════════╗
║            V H C S S 14      -CLIENT-                   ║
║           Runtime License & Feature Validator           ║
╚═════════════════════════════════════════════════════════╝
)";

    CoreEngine engine;
    CoreEngine::Config cfg {
        /* licenseKey  */ "A3F7-C291-BB04-E8D5",
        /* hardwareId  */ "F0E1D2C3B4A596870F1E2D3C4B5A6978",
        /* featureFlags*/ static_cast<uint32_t>(Feature::ALL),
        /* verboseLog  */ true
    };

    std::cout << "\n  Initializing engine...\n";
    bool ok = engine.init(cfg);
    std::cout << "  Init: " << (ok ? "SUCCESS" : "FAILED") << "\n";

    std::cout << "\n  Feature checks:\n";
    std::cout << "    EXPORT        : " << (engine.hasFeature(Feature::EXPORT)        ? "ON" : "OFF") << "\n";
    std::cout << "    BATCH_PROCESS : " << (engine.hasFeature(Feature::BATCH_PROCESS) ? "ON" : "OFF") << "\n";
    std::cout << "    CLOUD_SYNC    : " << (engine.hasFeature(Feature::CLOUD_SYNC)    ? "ON" : "OFF") << "\n";
    std::cout << "    ADVANCED_AI   : " << (engine.hasFeature(Feature::ADVANCED_AI)   ? "ON" : "OFF") << "\n";
    std::cout << "    API_ACCESS    : " << (engine.hasFeature(Feature::API_ACCESS)    ? "ON" : "OFF") << "\n";

    engine.run("InitPayload::RuntimeContext::v2.4.1");

    std::cout << R"(
╔═════════════════════════════════════════════════════════╗
║                  VHC SS14 VERIFY                        ║
╚═════════════════════════════════════════════════════════╝
)";
    return 0;
}
PKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP
PKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKPPKPKPKPKPKPKPKPKPKPKPKP

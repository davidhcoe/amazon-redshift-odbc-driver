#include "IdcTokenExchangePlugin.h"

#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

#include <rslog.h>
#include <aws/core/auth/AWSCredentialsProvider.h>
#include <aws/core/client/ClientConfiguration.h>
#include <aws/core/utils/HashingUtils.h>
#include <aws/core/utils/json/JsonSerializer.h>
#include <aws/sts/STSClient.h>
#include <aws/sts/model/AssumeRoleWithWebIdentityRequest.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include "IAMUtils.h"

using namespace Redshift::IamSupport;
using namespace Aws::SSOOIDC;
using namespace Aws::SSOOIDC::Model;
using namespace std::chrono;

namespace {
    /// RFC 7523 grant used to exchange an external IdP assertion for an IdC token.
    static const std::string JWT_BEARER_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    static const std::string REFRESH_TOKEN_GRANT_TYPE = "refresh_token";

    /// Matches rsodbc.h's RS_TOKEN_TYPE_ACCESS_TOKEN, which is not visible from iam/plugins.
    static const std::string ACCESS_TOKEN_TYPE = "ACCESS_TOKEN";

    /// Renew this far ahead of expiry so a token cannot lapse mid-connection.
    static const long long EXPIRY_SKEW_MILLIS = 60LL * 1000LL;

    /// How long a process waits for a sibling to finish its exchange before going ahead on its
    /// own. Generous on purpose: losing the race costs a wait, giving up early costs a failed
    /// connection.
    static const long long LOCK_WAIT_MILLIS = 60LL * 1000LL;

    struct CachedIdcToken {
        std::string accessToken;
        std::string refreshToken;
        long long   expiresAtMillis = 0;
    };

    // Process-wide, and backed by the on-disk cache below so that sibling processes do not each
    // have to redeem the assertion. Hosts such as Power BI evaluate one user action across
    // several concurrent processes while issuing them all the same external JWT.
    static std::unordered_map<std::string, CachedIdcToken> s_idcTokenCache;
    static std::mutex s_idcTokenCacheMutex;

    long long NowMillis() {
        return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
    }

    std::string Sha256Hex(const std::string& in_value) {
        const auto hash =
            Aws::Utils::HashingUtils::CalculateSHA256(Aws::String(in_value.c_str(), in_value.size()));
        return std::string(Aws::Utils::HashingUtils::HexEncode(hash).c_str());
    }

    /// Per user, never shared: the cached token carries one user's identity.
    std::string TokenCacheDirectory() {
#ifdef _WIN32
        const char* base = std::getenv("LOCALAPPDATA");
        return base == nullptr ? "" : std::string(base) + "\\Amazon\\Redshift\\IdcTokenCache";
#else
        const char* base = std::getenv("HOME");
        return base == nullptr ? "" : std::string(base) + "/.redshift/idc-token-cache";
#endif
    }

    bool EnsureDirectory(const std::string& in_dir) {
        if (in_dir.empty()) {
            return false;
        }
#ifdef _WIN32
        const char sep = '\\';
#else
        const char sep = '/';
#endif
        for (size_t i = 1; i <= in_dir.size(); ++i) {
            if (i != in_dir.size() && in_dir[i] != sep) {
                continue;
            }
            const std::string part = in_dir.substr(0, i);
#ifdef _WIN32
            // "C:" is not a creatable directory, so a failure there is expected.
            if (!CreateDirectoryA(part.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS &&
                !(part.size() == 2 && part[1] == ':')) {
                return false;
            }
#else
            if (mkdir(part.c_str(), 0700) != 0 && errno != EEXIST) {
                return false;
            }
#endif
        }
        return true;
    }

    /// Windows encrypts the file to the current user via DPAPI, so the token is not sitting in
    /// plain text at rest. Elsewhere the file is written owner-only.
    bool ProtectBytes(const std::string& in_plain, std::string& out_stored) {
#ifdef _WIN32
        DATA_BLOB input{};
        DATA_BLOB output{};
        input.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(in_plain.data()));
        input.cbData = static_cast<DWORD>(in_plain.size());
        if (!CryptProtectData(&input, L"RedshiftIdcToken", nullptr, nullptr, nullptr,
                              CRYPTPROTECT_UI_FORBIDDEN, &output)) {
            return false;
        }
        out_stored.assign(reinterpret_cast<char*>(output.pbData), output.cbData);
        LocalFree(output.pbData);
        return true;
#else
        out_stored = in_plain;
        return true;
#endif
    }

    bool UnprotectBytes(const std::string& in_stored, std::string& out_plain) {
#ifdef _WIN32
        DATA_BLOB input{};
        DATA_BLOB output{};
        input.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(in_stored.data()));
        input.cbData = static_cast<DWORD>(in_stored.size());
        if (!CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr,
                                CRYPTPROTECT_UI_FORBIDDEN, &output)) {
            return false;
        }
        out_plain.assign(reinterpret_cast<char*>(output.pbData), output.cbData);
        LocalFree(output.pbData);
        return true;
#else
        out_plain = in_stored;
        return true;
#endif
    }

    std::string CacheFilePath(const std::string& in_key) {
        const std::string dir = TokenCacheDirectory();
        if (dir.empty()) {
            return "";
        }
#ifdef _WIN32
        return dir + "\\" + in_key + ".bin";
#else
        return dir + "/" + in_key + ".bin";
#endif
    }

    bool ReadDiskToken(const std::string& in_key, CachedIdcToken& out_entry) {
        const std::string path = CacheFilePath(in_key);
        if (path.empty()) {
            return false;
        }

        std::ifstream file(path.c_str(), std::ios::binary);
        if (!file) {
            return false;
        }
        const std::string stored((std::istreambuf_iterator<char>(file)),
                                 std::istreambuf_iterator<char>());
        file.close();
        if (stored.empty()) {
            return false;
        }

        std::string plain;
        if (!UnprotectBytes(stored, plain)) {
            RS_LOG_DEBUG("IAMIDCX", "Cached IdC token could not be decrypted; ignoring it");
            return false;
        }

        Aws::Utils::Json::JsonValue json{Aws::String(plain.c_str(), plain.size())};
        if (!json.WasParseSuccessful()) {
            return false;
        }
        const auto view = json.View();
        out_entry.accessToken = view.GetString("accessToken").c_str();
        out_entry.refreshToken = view.GetString("refreshToken").c_str();
        out_entry.expiresAtMillis = static_cast<long long>(view.GetInt64("expiresAtMillis"));
        return !out_entry.accessToken.empty();
    }

    void WriteDiskToken(const std::string& in_key, const CachedIdcToken& in_entry) {
        if (!EnsureDirectory(TokenCacheDirectory())) {
            return;
        }
        const std::string path = CacheFilePath(in_key);
        if (path.empty()) {
            return;
        }

        Aws::Utils::Json::JsonValue json;
        json.WithString("accessToken", in_entry.accessToken.c_str())
            .WithString("refreshToken", in_entry.refreshToken.c_str())
            .WithInt64("expiresAtMillis", in_entry.expiresAtMillis);
        const Aws::String payload = json.View().WriteCompact();

        std::string stored;
        if (!ProtectBytes(std::string(payload.c_str(), payload.size()), stored)) {
            RS_LOG_DEBUG("IAMIDCX", "Could not protect the IdC token; not writing it to disk");
            return;
        }

        std::ofstream file(path.c_str(), std::ios::binary | std::ios::trunc);
        if (!file) {
            return;
        }
        file.write(stored.data(), static_cast<std::streamsize>(stored.size()));
        file.close();

#ifndef _WIN32
        chmod(path.c_str(), S_IRUSR | S_IWUSR);
#endif
    }

    void StoreToken(const std::string& in_key, const CachedIdcToken& in_entry) {
        {
            std::lock_guard<std::mutex> lock(s_idcTokenCacheMutex);
            s_idcTokenCache[in_key] = in_entry;
        }
        WriteDiskToken(in_key, in_entry);
    }

    bool IsUsable(const CachedIdcToken& in_entry, long long in_now) {
        return !in_entry.accessToken.empty() &&
               in_now < (in_entry.expiresAtMillis - EXPIRY_SKEW_MILLIS);
    }

    /// Serialises the cache-miss path across processes.
    ///
    /// The on-disk cache alone is not enough. Sibling processes are handed the same single-use
    /// assertion and may start together, so without this they race: both miss the cache, both
    /// call CreateTokenWithIAM, and the loser is rejected with "invalid_grant: JWT is already
    /// redeemed". Holding this lock across the exchange makes the loser wait and then find the
    /// winner's token on disk instead.
    ///
    /// Failing to take the lock is not fatal. The caller proceeds unserialised, which is no
    /// worse than having no lock at all.
    class CrossProcessLock {
    public:
        explicit CrossProcessLock(const std::string& in_key) {
#ifdef _WIN32
            // The key is SHA-256 hex, so widening it byte-for-byte is safe. "Local\" keeps the
            // mutex inside the caller's logon session, matching the per-user cache.
            const std::wstring name =
                L"Local\\RedshiftIdcTokenExchange_" + std::wstring(in_key.begin(), in_key.end());
            m_handle = CreateMutexW(nullptr, FALSE, name.c_str());
            if (m_handle != nullptr) {
                const DWORD waited =
                    WaitForSingleObject(m_handle, static_cast<DWORD>(LOCK_WAIT_MILLIS));
                // WAIT_ABANDONED means the holder died mid-exchange; the lock is ours now.
                m_held = (waited == WAIT_OBJECT_0 || waited == WAIT_ABANDONED);
            }
#else
            if (!EnsureDirectory(TokenCacheDirectory())) {
                return;
            }
            const std::string path = CacheFilePath(in_key) + ".lock";
            m_fd = open(path.c_str(), O_CREAT | O_RDWR, 0600);
            if (m_fd < 0) {
                return;
            }
            // flock has no timeout, so poll rather than risk blocking a connection forever.
            const long long deadline = NowMillis() + LOCK_WAIT_MILLIS;
            while (NowMillis() < deadline) {
                if (flock(m_fd, LOCK_EX | LOCK_NB) == 0) {
                    m_held = true;
                    return;
                }
                std::this_thread::sleep_for(milliseconds(100));
            }
#endif
        }

        ~CrossProcessLock() {
#ifdef _WIN32
            if (m_handle != nullptr) {
                if (m_held) {
                    ReleaseMutex(m_handle);
                }
                CloseHandle(m_handle);
            }
#else
            if (m_fd >= 0) {
                if (m_held) {
                    flock(m_fd, LOCK_UN);
                }
                close(m_fd);
            }
#endif
        }

        CrossProcessLock(const CrossProcessLock&) = delete;
        CrossProcessLock& operator=(const CrossProcessLock&) = delete;

        bool Held() const { return m_held; }

    private:
        bool m_held = false;
#ifdef _WIN32
        HANDLE m_handle = nullptr;
#else
        int m_fd = -1;
#endif
    };
}

IdcTokenExchangePlugin::IdcTokenExchangePlugin(
    const IAMConfiguration& in_config,
    const std::map<rs_string, rs_string>& in_argsMap)
    : NativePluginCredentialsProvider(in_config, in_argsMap) {
    RS_LOG_DEBUG("IAMIDCX", "IdcTokenExchangePlugin::IdcTokenExchangePlugin");
    InitArgumentsMap();
}

IdcTokenExchangePlugin::~IdcTokenExchangePlugin() {
    RS_LOG_DEBUG("IAMIDCX", "IdcTokenExchangePlugin::~IdcTokenExchangePlugin");
}

void IdcTokenExchangePlugin::InitArgumentsMap() {
    RS_LOG_DEBUG("IAMIDCX", "IdcTokenExchangePlugin::InitArgumentsMap");

    const rs_string authToken = IAMUtils::rs_trim(m_config.GetIdpAuthToken());
    if (!authToken.empty()) {
        m_argsMap[KEY_IDP_AUTH_TOKEN] = authToken;
    }

    const rs_string idcRegion = IAMUtils::rs_trim(m_config.GetIdcRegion());
    if (!idcRegion.empty()) {
        m_argsMap[KEY_IDC_REGION] = idcRegion;
        RS_LOG_DEBUG("IAMIDCX", "Setting idc_region=%s", idcRegion.c_str());
    }

    // See the header: issuer_url carries the IdC managed application ARN in this PoC.
    const rs_string applicationArn = IAMUtils::rs_trim(m_config.GetIssuerUrl());
    if (!applicationArn.empty()) {
        m_argsMap[KEY_IDC_ISSUER_URL] = applicationArn;
        RS_LOG_DEBUG("IAMIDCX", "Setting idc application arn=%s", applicationArn.c_str());
    }

    const rs_string roleArn = IAMUtils::rs_trim(m_config.GetRoleARN());
    if (!roleArn.empty()) {
        m_argsMap[IAM_KEY_ROLE_ARN] = roleArn;
        RS_LOG_DEBUG("IAMIDCX", "Setting role_arn=%s", roleArn.c_str());
    }
}

void IdcTokenExchangePlugin::ValidateArgumentsMap() {
    RS_LOG_DEBUG("IAMIDCX", "IdcTokenExchangePlugin::ValidateArgumentsMap");

    if (!m_argsMap.count(KEY_IDP_AUTH_TOKEN)) {
        RS_LOG_ERROR("IAMIDCX", "IdC token exchange failed: no token provided");
        IAMUtils::ThrowConnectionExceptionWithInfo(
            "IdC token exchange failed: The external IdP token must be included in the "
            "connection parameters as 'token'.");
    }
    if (!m_argsMap.count(KEY_IDC_REGION)) {
        RS_LOG_ERROR("IAMIDCX", "IdC token exchange failed: no idc_region provided");
        IAMUtils::ThrowConnectionExceptionWithInfo(
            "IdC token exchange failed: The IdC region must be included in the "
            "connection parameters as 'idc_region'.");
    }
    if (!m_argsMap.count(KEY_IDC_ISSUER_URL)) {
        RS_LOG_ERROR("IAMIDCX", "IdC token exchange failed: no application ARN provided");
        IAMUtils::ThrowConnectionExceptionWithInfo(
            "IdC token exchange failed: The IdC managed application ARN must be included in "
            "the connection parameters as 'issuer_url'.");
    }
    if (!m_argsMap.count(IAM_KEY_ROLE_ARN)) {
        RS_LOG_ERROR("IAMIDCX", "IdC token exchange failed: no role_arn provided");
        IAMUtils::ThrowConnectionExceptionWithInfo(
            "IdC token exchange failed: The IAM role to assume with the external token must be "
            "included in the connection parameters as 'role_arn'.");
    }
}

rs_string IdcTokenExchangePlugin::GetCacheKey() const {
    // The assertion is part of the key, not just the application and region: two users of the
    // same application must never share an entry, and a new sign-in must not resurrect the
    // previous user's token. Hashed so the key is safe to use as a file name.
    return Sha256Hex(m_argsMap.at(KEY_IDC_ISSUER_URL) + "|" + m_argsMap.at(KEY_IDC_REGION) + "|" +
                     m_argsMap.at(KEY_IDP_AUTH_TOKEN));
}

Aws::Auth::AWSCredentials IdcTokenExchangePlugin::AssumeRoleWithAssertion(const rs_string& in_region) {
    RS_LOG_DEBUG("IAMIDCX", "Exchanging the external JWT for temporary AWS credentials");

    Aws::Client::ClientConfiguration config;
    config.region = in_region;

#ifndef _WIN32
    config.caFile = m_config.GetCaFile().empty()
                        ? IAMUtils::convertToUTF8(IAMUtils::GetDefaultCaFile())
                        : m_config.GetCaFile();
#endif

    if (m_config.GetUsingHTTPSProxy() && m_config.GetUseProxyIdpAuth()) {
        config.proxyHost = m_config.GetHTTPSProxyHost();
        config.proxyPort = m_config.GetHTTPSProxyPort();
        if (!m_config.GetHTTPSProxyUser().empty()) {
            config.proxyUserName = m_config.GetHTTPSProxyUser();
        }
        if (!m_config.GetHTTPSProxyPassword().empty()) {
            config.proxyPassword = m_config.GetHTTPSProxyPassword();
        }
    }

    // Anonymous on purpose: AssumeRoleWithWebIdentity is unsigned, the JWT is the credential.
    Aws::STS::STSClient client(
        Aws::MakeShared<Aws::Auth::AnonymousAWSCredentialsProvider>("IAMIDCX"), config);

    Aws::STS::Model::AssumeRoleWithWebIdentityRequest request;
    request.SetWebIdentityToken(m_argsMap[KEY_IDP_AUTH_TOKEN]);
    request.SetRoleArn(m_argsMap[IAM_KEY_ROLE_ARN]);
    request.SetRoleSessionName("redshift-idc-token-exchange");

    auto outcome = client.AssumeRoleWithWebIdentity(request);
    if (!outcome.IsSuccess()) {
        const auto& error = outcome.GetError();
        const rs_string message = error.GetExceptionName() + ": " + error.GetMessage();
        RS_LOG_ERROR("IAMIDCX", "AssumeRoleWithWebIdentity failed: %s", message.c_str());
        IAMUtils::ThrowConnectionExceptionWithInfo(
            "IdC token exchange failed: could not assume role_arn with the external token. " +
            message);
    }

    const auto& creds = outcome.GetResult().GetCredentials();
    RS_LOG_DEBUG("IAMIDCX", "Temporary AWS credentials acquired");
    return Aws::Auth::AWSCredentials(
        creds.GetAccessKeyId(), creds.GetSecretAccessKey(), creds.GetSessionToken());
}

void IdcTokenExchangePlugin::InitializeIdcClient(const rs_string& in_region) {
    RS_LOG_DEBUG("IAMIDCX", "IdcTokenExchangePlugin::InitializeIdcClient region=%s", in_region.c_str());

    Aws::Client::ClientConfiguration clientConfig;
    clientConfig.region = in_region;

    if (m_config.GetUsingHTTPSProxy() && m_config.GetUseProxyIdpAuth()) {
        clientConfig.proxyHost = m_config.GetHTTPSProxyHost();
        clientConfig.proxyPort = m_config.GetHTTPSProxyPort();
        if (!m_config.GetHTTPSProxyUser().empty()) {
            clientConfig.proxyUserName = m_config.GetHTTPSProxyUser();
        }
        if (!m_config.GetHTTPSProxyPassword().empty()) {
            clientConfig.proxyPassword = m_config.GetHTTPSProxyPassword();
        }
    }

    pIdcClient_ = std::make_shared<SSOOIDCClient>(AssumeRoleWithAssertion(in_region), clientConfig);
}

rs_string IdcTokenExchangePlugin::GetAuthToken() {
    RS_LOG_DEBUG("IAMIDCX", "IdcTokenExchangePlugin::GetAuthToken");

    ValidateArgumentsMap();

    const rs_string cacheKey = GetCacheKey();

    CachedIdcToken cached;
    bool haveCached = false;
    {
        std::lock_guard<std::mutex> lock(s_idcTokenCacheMutex);
        auto it = s_idcTokenCache.find(cacheKey);
        if (it != s_idcTokenCache.end()) {
            cached = it->second;
            haveCached = true;
        }
    }

    // Each process starts with an empty map but they all share one single-use assertion, so the
    // on-disk copy has to be consulted before considering another exchange.
    if (!haveCached && ReadDiskToken(cacheKey, cached)) {
        RS_LOG_DEBUG("IAMIDCX", "Loaded the IdC token from the on-disk cache");
        haveCached = true;
        std::lock_guard<std::mutex> lock(s_idcTokenCacheMutex);
        s_idcTokenCache[cacheKey] = cached;
    }

    if (haveCached && IsUsable(cached, NowMillis())) {
        RS_LOG_DEBUG("IAMIDCX", "Reusing cached IdC token; the external JWT is not re-exchanged");
        m_argsMap[KEY_IDP_AUTH_TOKEN_TYPE] = ACCESS_TOKEN_TYPE;
        return cached.accessToken;
    }

    // Cache miss. A sibling process may be exchanging this very assertion right now, so take the
    // cross-process lock and look again before spending it.
    CrossProcessLock exchangeLock(cacheKey);
    if (!exchangeLock.Held()) {
        RS_LOG_DEBUG("IAMIDCX",
                     "Proceeding without the cross-process exchange lock; a concurrent process "
                     "may redeem the same assertion");
    }

    // Read into a separate entry: a failed read must not clobber the expired token above, whose
    // refresh token is still needed by the fallback below.
    CachedIdcToken fromDisk;
    if (ReadDiskToken(cacheKey, fromDisk) && IsUsable(fromDisk, NowMillis())) {
        RS_LOG_DEBUG("IAMIDCX", "Another process completed the exchange while we waited");
        {
            std::lock_guard<std::mutex> lock(s_idcTokenCacheMutex);
            s_idcTokenCache[cacheKey] = fromDisk;
        }
        m_argsMap[KEY_IDP_AUTH_TOKEN_TYPE] = ACCESS_TOKEN_TYPE;
        return fromDisk.accessToken;
    }

    InitializeIdcClient(m_argsMap[KEY_IDC_REGION]);

    if (haveCached && !cached.refreshToken.empty()) {
        RS_LOG_DEBUG("IAMIDCX", "Cached IdC token expired; refreshing without a new external JWT");
        const rs_string refreshed = RefreshIdcToken(cached.refreshToken);
        if (!refreshed.empty()) {
            m_argsMap[KEY_IDP_AUTH_TOKEN_TYPE] = ACCESS_TOKEN_TYPE;
            return refreshed;
        }
        RS_LOG_DEBUG("IAMIDCX", "Refresh failed; falling back to a full exchange");
    }

    const rs_string exchanged = ExchangeAssertionForIdcToken();
    m_argsMap[KEY_IDP_AUTH_TOKEN_TYPE] = ACCESS_TOKEN_TYPE;
    return exchanged;
}

rs_string IdcTokenExchangePlugin::ExchangeAssertionForIdcToken() {
    RS_LOG_DEBUG("IAMIDCX", "Exchanging the external JWT for an IdC token (jwt-bearer)");

    CreateTokenWithIAMRequest request;
    request.SetClientId(m_argsMap[KEY_IDC_ISSUER_URL]);
    request.SetGrantType(JWT_BEARER_GRANT_TYPE);
    request.SetAssertion(m_argsMap[KEY_IDP_AUTH_TOKEN]);

    CreateTokenWithIAMOutcome outcome = pIdcClient_->CreateTokenWithIAM(request);
    if (!outcome.IsSuccess()) {
        HandleCreateTokenWithIAMError(outcome);
    }

    const auto& result = outcome.GetResult();
    if (result.GetAccessToken().empty()) {
        IAMUtils::ThrowConnectionExceptionWithInfo(
            "IdC token exchange failed: CreateTokenWithIAM returned an empty access token.");
    }

    CachedIdcToken entry;
    entry.accessToken = result.GetAccessToken();
    entry.refreshToken = result.GetRefreshToken();
    entry.expiresAtMillis = NowMillis() + (static_cast<long long>(result.GetExpiresIn()) * 1000LL);

    StoreToken(GetCacheKey(), entry);

    RS_LOG_DEBUG("IAMIDCX", "IdC token acquired, expires_in=%d, refresh token %s",
                 result.GetExpiresIn(), entry.refreshToken.empty() ? "absent" : "cached");
    return entry.accessToken;
}

rs_string IdcTokenExchangePlugin::RefreshIdcToken(const rs_string& in_refreshToken) {
    RS_LOG_DEBUG("IAMIDCX", "Refreshing the IdC token");

    CreateTokenWithIAMRequest request;
    request.SetClientId(m_argsMap[KEY_IDC_ISSUER_URL]);
    request.SetGrantType(REFRESH_TOKEN_GRANT_TYPE);
    request.SetRefreshToken(in_refreshToken);

    CreateTokenWithIAMOutcome outcome = pIdcClient_->CreateTokenWithIAM(request);
    if (!outcome.IsSuccess()) {
        RS_LOG_DEBUG("IAMIDCX", "IdC refresh failed: %s",
                     outcome.GetError().GetMessage().c_str());
        return "";
    }

    const auto& result = outcome.GetResult();
    if (result.GetAccessToken().empty()) {
        return "";
    }

    CachedIdcToken entry;
    entry.accessToken = result.GetAccessToken();
    entry.refreshToken = result.GetRefreshToken().empty() ? in_refreshToken : result.GetRefreshToken();
    entry.expiresAtMillis = NowMillis() + (static_cast<long long>(result.GetExpiresIn()) * 1000LL);

    StoreToken(GetCacheKey(), entry);

    return entry.accessToken;
}

void IdcTokenExchangePlugin::HandleCreateTokenWithIAMError(
    const CreateTokenWithIAMOutcome& in_outcome) {
    const auto& error = in_outcome.GetError();
    const std::string message = error.GetExceptionName() + ": " + error.GetMessage();

    RS_LOG_ERROR("IAMIDCX", "CreateTokenWithIAM failed - Response code:%d; %s",
                 static_cast<int>(error.GetResponseCode()), message.c_str());

    IAMUtils::ThrowConnectionExceptionWithInfo("IdC token exchange failed: " + message);
}

#include "IdcTokenExchangePlugin.h"

#include <chrono>
#include <mutex>
#include <string>
#include <unordered_map>

#include <rslog.h>
#include <aws/core/client/ClientConfiguration.h>

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

    struct CachedIdcToken {
        std::string accessToken;
        std::string refreshToken;
        long long   expiresAtMillis = 0;
    };

    // Process-wide, as RsIamHelper's credential cache already is. A multi-user host would
    // need the key widened to include the caller identity.
    static std::unordered_map<std::string, CachedIdcToken> s_idcTokenCache;
    static std::mutex s_idcTokenCacheMutex;

    long long NowMillis() {
        return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
    }
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
}

rs_string IdcTokenExchangePlugin::GetCacheKey() const {
    return m_argsMap.at(KEY_IDC_ISSUER_URL) + "|" + m_argsMap.at(KEY_IDC_REGION);
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

    // PoC only: signs with the SDK default credential chain. Production depends on IdC
    // accepting the jwt-bearer grant without SigV4.
    pIdcClient_ = std::make_shared<SSOOIDCClient>(clientConfig);
}

rs_string IdcTokenExchangePlugin::GetAuthToken() {
    RS_LOG_DEBUG("IAMIDCX", "IdcTokenExchangePlugin::GetAuthToken");

    ValidateArgumentsMap();

    const rs_string cacheKey = GetCacheKey();
    const long long now = NowMillis();

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

    if (haveCached && now < (cached.expiresAtMillis - EXPIRY_SKEW_MILLIS)) {
        RS_LOG_DEBUG("IAMIDCX", "Reusing cached IdC token; the external JWT is not re-exchanged");
        m_argsMap[KEY_IDP_AUTH_TOKEN_TYPE] = ACCESS_TOKEN_TYPE;
        return cached.accessToken;
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

    {
        std::lock_guard<std::mutex> lock(s_idcTokenCacheMutex);
        s_idcTokenCache[GetCacheKey()] = entry;
    }

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

    {
        std::lock_guard<std::mutex> lock(s_idcTokenCacheMutex);
        s_idcTokenCache[GetCacheKey()] = entry;
    }

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

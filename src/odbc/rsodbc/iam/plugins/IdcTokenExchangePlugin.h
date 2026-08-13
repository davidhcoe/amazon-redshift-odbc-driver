#ifndef _IDCTOKENEXCHANGEPLUGIN_H_
#define _IDCTOKENEXCHANGEPLUGIN_H_

#include "NativePluginCredentialsProvider.h"

#include <aws/sso-oidc/SSOOIDCClient.h>
#include <aws/sso-oidc/model/CreateTokenWithIAMRequest.h>
#include <aws/sso-oidc/model/CreateTokenWithIAMResult.h>

namespace Redshift
{
    namespace IamSupport
    {
        /**
         * @brief Exchanges an external IdP token for an IAM Identity Center token, once,
         *        and reuses the result across connections.
         *
         * Motivation
         * ----------
         * With plugin_name=IdpTokenAuthPlugin and token_type=EXT_JWT the driver forwards the
         * external JWT to Redshift, which exchanges it at IdC on every connection. That
         * exchange is single-use: measured against a live environment, the second connection
         * with the same still-valid token fails 855 ms after the first with
         * "28000 FATAL: Token credentials expired or invalid".
         *
         * This plugin performs the exchange itself, caches the resulting IdC token, and sends
         * token_type=ACCESS_TOKEN thereafter -- the same wire format BrowserIdcAuthPlugin
         * already uses, which Redshift accepts without any further exchange. The external JWT
         * is therefore used exactly once. Validated: one exchanged IdC token carried four
         * consecutive connections with zero authentication failures.
         *
         * PROOF OF CONCEPT
         * ----------------
         * sso-oidc:CreateTokenWithIAM requires SigV4, so this build signs the exchange with
         * whatever the AWS SDK default credential chain resolves (environment, profile,
         * instance role). A real client authenticating a user through an external IdP has no
         * AWS credentials, so shipping this depends on IdC accepting the jwt-bearer grant
         * without SigV4. That single change is the ask; everything else here works today.
         *
         * Connection parameters (all already plumbed, none new):
         *   plugin_name  = IdcTokenExchangePlugin
         *   token        = the external IdP JWT
         *   idc_region   = region of the IdC instance
         *   issuer_url   = the IdC *managed application* ARN.
         *                  Reused deliberately: this flow has no RegisterClient step, so
         *                  issuer_url is otherwise unused and carrying the ARN here avoids
         *                  threading a new setting through rsconnect/RsSettings/IAMConfiguration.
         *                  A production implementation should add a dedicated
         *                  idc_application_arn parameter instead.
         */
        class IdcTokenExchangePlugin : public NativePluginCredentialsProvider
        {
        public:
            explicit IdcTokenExchangePlugin(
                const IAMConfiguration& in_config = IAMConfiguration(),
                const std::map<rs_string, rs_string>& in_argsMap = std::map<rs_string, rs_string>());

            /// @brief Returns an IdC access token, exchanging or refreshing only when needed.
            rs_string GetAuthToken() override;

            ~IdcTokenExchangePlugin();

        private:
            std::shared_ptr<Aws::SSOOIDC::SSOOIDCClient> pIdcClient_;

            void InitArgumentsMap() override;
            void ValidateArgumentsMap() override;

            void InitializeIdcClient(const rs_string& in_region);

            /// @brief CreateTokenWithIAM with the jwt-bearer grant, assertion = external JWT.
            rs_string ExchangeAssertionForIdcToken();

            /// @brief CreateTokenWithIAM with the refresh_token grant.
            rs_string RefreshIdcToken(const rs_string& in_refreshToken);

            void HandleCreateTokenWithIAMError(
                const Aws::SSOOIDC::Model::CreateTokenWithIAMOutcome& in_outcome);

            /// @brief Cache key for the exchanged token: application ARN + region.
            rs_string GetCacheKey() const;
        };
    }
}

#endif

import unittest
import responses

import wideq.core


class SimpleTest(unittest.TestCase):
    @responses.activate
    def test_gateway_en_US(self):
        # these are the relevant parts of a real response
        gateway_response = {
            "resultCode": "0000",
            "result": {
                "countryCode": "US",
                "languageCode": "en-US",
                "thinq1Uri": "https://aic.lgthinq.com:46030/api",
                "thinq2Uri": "https://aic-service.lgthinq.com:46030/v1",
                "empUri": "https://us.m.lgaccount.com",
                "empSpxUri": "https://us.m.lgaccount.com/spx",
                "rtiUri": "aic.lgthinq.com:47878",
                "mediaUri": "aic-media.lgthinq.com:47800",
                "appLatestVer": "3.0.1700001",
                "appUpdateYn": "N",
                "appLink": "market://details?id=com.lgeha.nuts",
                "nestSupportAppVer": "9.0.0",
                "uuidLoginYn": "Y",
                "lineLoginYn": "N",
                "lineChannelId": "",
                "cicTel": "800-243-0000",
                "cicUri": "",
                "isSupportVideoYn": "N",
                "countryLangDescription": "USA/English",
                "racUri": "us.rac.lgeapi.com",
                "amazonDrsYn": "Y",
                "features": {
                    "amazonDrs": "Y",
                    "pccPushProd": "101,201,202,204,301,401",
                    "cicSupport": "Y",
                    "pccPush": "Y",
                    "pccWarrantyProd": "101,201,202,204,301,401",
                    "pccWarranty": "Y"
                },
            }
        }
        responses.add(
            responses.GET,
            wideq.core.V2_GATEWAY_URL,
            json=gateway_response
        )
        gatewayInstance = wideq.core.Gateway.discover('US', 'en-US')
        self.assertEqual(len(responses.calls), 1)
        self.assertEqual(gatewayInstance.country, 'US')
        self.assertEqual(gatewayInstance.language, 'en-US')
        self.assertEqual(gatewayInstance.auth_base,
                         'https://us.m.lgaccount.com')
        self.assertEqual(gatewayInstance.api_root,
                         'https://aic-service.lgthinq.com:46030/v1')
        self.assertEqual(gatewayInstance.oauth_root,
                         'https://us.m.lgaccount.com')

    @responses.activate
    def test_gateway_en_NO(self):
        # these are the relevant parts of a real response
        gateway_response = {
            "resultCode": "0000",
            "result": {
                "countryCode": "NO",
                "languageCode": "en-NO",
                "thinq1Uri": "https://eic.lgthinq.com:46030/api",
                "thinq2Uri": "https://eic-service.lgthinq.com:46030/v1",
                "empUri": "https://no.m.lgaccount.com",
                "empSpxUri": "https://no.m.lgaccount.com/spx",
                "rtiUri": "eic.lgthinq.com:47878",
                "mediaUri": "eic-media.lgthinq.com:47800",
                "appLatestVer": "3.0.1700001",
                "appUpdateYn": "N",
                "appLink": "market://details?id=com.lgeha.nuts",
                "uuidLoginYn": "N",
                "lineLoginYn": "N",
                "lineChannelId": "",
                "cicTel": "815-691-54",
                "cicUri": "",
                "isSupportVideoYn": "N",
                "countryLangDescription": "Norway/English",
                "racUri": "no.rac.lgeapi.com",
                "amazonDrsYn": "N",
                "features": {
                    "cicSupport": "Y"
                },
                "serviceCards": []
            }
        }

        responses.add(
            responses.GET,
            wideq.core.V2_GATEWAY_URL,
            json=gateway_response
        )
        gatewayInstance = wideq.core.Gateway.discover('NO', 'en-NO')
        self.assertEqual(len(responses.calls), 1)
        self.assertEqual(gatewayInstance.country, 'NO')
        self.assertEqual(gatewayInstance.language, 'en-NO')
        self.assertEqual(gatewayInstance.auth_base,
                         'https://no.m.lgaccount.com')
        self.assertEqual(gatewayInstance.api_root,
                         'https://eic-service.lgthinq.com:46030/v1')
        self.assertEqual(gatewayInstance.oauth_root,
                         'https://no.m.lgaccount.com')

/*
 * Copyright 2015 Francois Steyn - Adept Internet (PTY) LTD (francois.s@adept.co.za).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.adeptnet.auth.sso;

import java.util.Map;
import java.util.logging.Logger;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.adeptnet.auth.saml.SAMLClient;
import org.adeptnet.auth.saml.SAMLConfigImpl;
import org.adeptnet.auth.saml.SAMLException;
import org.opensaml.ws.message.encoder.MessageEncodingException;

/**
 *
 * @author Francois Steyn - Adept Internet (PTY) LTD (francois.s@adept.co.za)
 */
public class Common {

    private static final Logger LOG = Logger.getLogger(Common.class.getName());

    private final static String SAML_ENABLE = "saml-enable";
    private final static String SAML_IDP_CONFIG = "saml-idp-config";
    private final static String SAML_SP_CONFIG = "saml-sp-config";
    private final static String SAML_KEYSTORE_NAME = "saml-keystore-name";
    private final static String SAML_KEYSTORE_PASSWORD = "saml-keystore-password";
    private final static String SAML_CERTIFICATE_ALIAS = "saml-certificate-alias";

    private static Common common;

    private SAMLClient samlClient;
    private final SAMLConfigImpl samlCfg;
    private final boolean samlEnabled;

    private Common(final SAMLConfigImpl samlCfg, final boolean samlEnabled) {
        this.samlCfg = samlCfg;
        this.samlEnabled = samlEnabled;
    }

    static void init(final SAMLConfigImpl samlCfg, final boolean samlEnabled) {
        final Common _common = new Common(samlCfg, samlEnabled);
        common = _common;
    }

    private static String getOption(final Map<?, ?> options, final String optionName) throws SAMLException {
        if (!options.containsKey(optionName)) {
            throw new SAMLException(String.format("Option [%s] not found", optionName));
        }
        final Object result = options.get(optionName);
        if (result instanceof String) {
            return (String) result;
        }
        throw new SAMLException(String.format("Option [%s] is not String [%s] - %s", optionName, result == null ? "NULL" : result.getClass(), result));
    }

    static void init(final Map<?, ?> options) throws SAMLException {
        final SAMLConfigImpl samlCfg = new SAMLConfigImpl();
        samlCfg.setIdpConfigName(getOption(options, SAML_IDP_CONFIG));
        samlCfg.setSpConfigName(getOption(options, SAML_SP_CONFIG));
        samlCfg.setKeystoreName(getOption(options, SAML_KEYSTORE_NAME));
        samlCfg.setKeystorePassword(getOption(options, SAML_KEYSTORE_PASSWORD));
        samlCfg.setCertificateAlias(getOption(options, SAML_CERTIFICATE_ALIAS));
        init(samlCfg, Boolean.parseBoolean(getOption(options, SAML_ENABLE)));
    }

    static Common getInstance() throws SAMLException {
        if (common == null) {
            throw new SAMLException("please init");
        }
        return common;
    }

    static Common getInstance(final Map<?, ?> options) throws SAMLException {
        if (common == null) {
            init(options);
            return getInstance();
        }
        return common;
    }

    private SAMLClient getSAMLClient() throws SAMLException {
        if (samlClient == null) {
            samlCfg.init();
            samlClient = new SAMLClient(samlCfg);
        }
        return samlClient;
    }

    public void doSAMLRedirect(final HttpServletRequest request, final HttpServletResponse response, final String relayState) throws SAMLException, MessageEncodingException {
        if (!samlEnabled) {
            throw new SAMLException("SAML is not enabled");
        }
        final SAMLClient client = getSAMLClient();
        client.doSAMLRedirect(response, relayState);
    }
}

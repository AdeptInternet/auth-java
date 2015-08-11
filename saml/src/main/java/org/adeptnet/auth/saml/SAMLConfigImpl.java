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
package org.adeptnet.auth.saml;

import java.io.File;
import java.util.function.Function;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Francois Steyn - Adept Internet (PTY) LTD (francois.s@adept.co.za)
 */
public class SAMLConfigImpl implements SAMLConfig {

    private static final Logger LOG = Logger.getLogger(SAMLConfigImpl.class.getName());

    private IdPConfig idpConfig;
    private String idpConfigName;
    private SPConfig spConfig;
    private String spConfigName;
    private File keystore;
    private String keystoreName;
    private char[] keystorePassword;
    private String certificateAlias;

    @Override
    public IdPConfig getIdPConfig() {
        return idpConfig;
    }

    @Override
    public SPConfig getSPConfig() {
        return spConfig;
    }

    public void setIdpConfig(final IdPConfig idpConfig) {
        this.idpConfig = idpConfig;
    }

    public SAMLConfigImpl withIdpConfig(final IdPConfig idpConfig) {
        setIdpConfig(idpConfig);
        return this;
    }

    public void setSpConfig(final SPConfig spConfig) {
        this.spConfig = spConfig;
    }

    public SAMLConfigImpl withSpConfig(final SPConfig spConfig) {
        setSpConfig(spConfig);
        return this;
    }

    @Override
    public File getKeystore() {
        return keystore;
    }

    public void setKeystore(final File keystore) {
        this.keystore = keystore;
    }

    public SAMLConfigImpl withKeystore(final File keystore) {
        setKeystore(keystore);
        return this;
    }

    @Override
    public char[] getKeystorePassword() {
        return keystorePassword;
    }

    public void setKeystorePassword(final char[] keystorePassword) {
        if (keystorePassword == null) {
            throw new NullPointerException("keystorePassword should never be null");
        }
        this.keystorePassword = keystorePassword;
    }

    public SAMLConfigImpl withKeystorePassword(final char[] keystorePassword) {
        setKeystorePassword(keystorePassword);
        return this;
    }

    public void setKeystorePassword(final String keystorePassword) {
        if (keystorePassword == null) {
            throw new NullPointerException("keystorePassword should never be null");
        }
        setKeystorePassword(keystorePassword.toCharArray());
    }

    public SAMLConfigImpl withKeystorePassword(final String keystorePassword) {
        setKeystorePassword(keystorePassword);
        return this;
    }

    @Override
    public String getCertificateAlias() {
        return certificateAlias;
    }

    public void setCertificateAlias(final String certificateAlias) {
        if (certificateAlias == null) {
            throw new NullPointerException("certificateAlias should never be null");
        }
        this.certificateAlias = certificateAlias;
    }

    public SAMLConfigImpl withCertificateAlias(final String certificateAlias) {
        setCertificateAlias(certificateAlias);
        return this;
    }

    public String getKeystoreName() {
        return keystoreName;
    }

    public void setKeystoreName(String keystoreName) {
        if (keystoreName == null) {
            throw new NullPointerException("keystoreName should never be null");
        }
        this.keystoreName = keystoreName;
    }

    public SAMLConfigImpl withKeystoreName(String keystoreName) {
        setKeystoreName(keystoreName);
        return this;
    }

    public String getIdpConfigName() {
        return idpConfigName;
    }

    public void setIdpConfigName(final String idpConfigName) {
        if (idpConfigName == null) {
            throw new NullPointerException("idpConfigName should never be null");
        }
        this.idpConfigName = idpConfigName;
    }

    public SAMLConfigImpl withIdpConfigName(final String idpConfigName) {
        setIdpConfigName(idpConfigName);
        return this;
    }

    public String getSpConfigName() {
        return spConfigName;
    }

    public void setSpConfigName(final String spConfigName) {
        if (spConfigName == null) {
            throw new NullPointerException("spConfigName should never be null");
        }
        this.spConfigName = spConfigName;
    }

    public SAMLConfigImpl withSpConfigName(final String spConfigName) {
        setSpConfigName(spConfigName);
        return this;
    }

    public SAMLConfigImpl init(final Function<String, String> function) throws SAMLException {
        SAMLInit.initialize();
        if (keystore == null) {
            final String fileName = function.apply(getKeystoreName());
            if (LOG.isLoggable(Level.FINE)) {
                LOG.fine(String.format("%s: %s", "KeystoreName", fileName));
            }
            keystore = new File(fileName);
        }
        if (idpConfig == null) {
            final String fileName = function.apply(getIdpConfigName());
            if (LOG.isLoggable(Level.FINE)) {
                LOG.fine(String.format("%s: %s", "IdpConfigName", fileName));
            }
            idpConfig = new IdPConfig(new File(fileName));
        }

        if (spConfig == null) {
            final String fileName = function.apply(getSpConfigName());
            if (LOG.isLoggable(Level.FINE)) {
                LOG.fine(String.format("%s: %s", "SpConfigName", fileName));
            }
            spConfig = new SPConfig(new File(fileName));
        }

        return this;
    }

    public SAMLConfigImpl init() throws SAMLException {
        return init((filename) -> {
            return filename;
        });
    }
}

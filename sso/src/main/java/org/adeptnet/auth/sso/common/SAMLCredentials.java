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
package org.adeptnet.auth.sso.common;

/**
 *
 * @author Francois Steyn - Adept Internet (PTY) LTD (francois.s@adept.co.za)
 */
public class SAMLCredentials implements SSOCredentials {

    private static final long serialVersionUID = 20150101001L;

    private final String server;
    private final boolean isGET;
    private final String ticket;
    private final String queryString;
    private final String origin;

    public SAMLCredentials(final String server, final boolean isGET, final String ticket, final String queryString, final String origin) {
        this.server = server;
        this.isGET = isGET;
        this.ticket = ticket;
        this.queryString = queryString;
        this.origin = origin;
    }

    public String getServer() {
        return server;
    }

    @Override
    public String getOrigin() {
        return origin;
    }

    public boolean isIsGET() {
        return isGET;
    }

    public String getTicket() {
        return ticket;
    }

    public String getQueryString() {
        return queryString;
    }

    @Override
    public String toString() {
        return "SAMLCredentials{" + "server=" + server + ", isGET=" + isGET + ", ticket=" + ticket + ", queryString=" + queryString + ", origin=" + origin + '}';
    }

}

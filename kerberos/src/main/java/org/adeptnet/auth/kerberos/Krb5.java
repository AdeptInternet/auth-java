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
package org.adeptnet.auth.kerberos;

import java.security.Principal;
import java.security.PrivilegedExceptionAction;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import javax.naming.NamingException;
import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import org.adeptnet.auth.common.Nameserver;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

/**
 *
 * @author Francois Steyn - Adept Internet (PTY) LTD (francois.s@adept.co.za)
 */
public class Krb5 {

    public static final String CREDS = "javax.security.auth.useSubjectCredsOnly";
    public static final String WWW_AUTHENTICATE = "WWW-Authenticate";
    public static final String AUTHORIZATION = "Authorization";
    public static final String NEGOTIATE = "Negotiate";
    public static final String FAILED = "FAILED";

    private static final Log LOG = LogFactory.getLog(Krb5.class);

    private final Krb5Config config;

    public Krb5(final Krb5Config config) {
        this.config = config;
    }

    private Configuration getJaasKrb5TicketCfg(final String principal) {
        return new Configuration() {
            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                Map<String, String> options = new HashMap<>();
                options.put("principal", principal);
                options.put("realm", config.getRealm());
                options.put("keyTab", config.getKeytab().getAbsolutePath());
                options.put("doNotPrompt", "true");
                options.put("useKeyTab", "true");
                options.put("storeKey", "true");
                options.put("isInitiator", "false");

                return new AppConfigurationEntry[]{
                    new AppConfigurationEntry(
                    "com.sun.security.auth.module.Krb5LoginModule",
                    AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options)
                };
            }
        };
    }

    private void checkCreds() {
        if (!System.getProperties().containsKey(Krb5.CREDS)) {
            LOG.warn(String.format("Setting [%s] to false", Krb5.CREDS));
            System.setProperty(Krb5.CREDS, "false");
        }
    }

    public String isTicketValid(String spn, byte[] ticket) {
        checkCreds();
        LoginContext ctx = null;
        try {
            if (!config.getKeytab().exists()) {
                throw new LoginException(String.format("KeyTab does not exist: %s", config.getKeytab().getAbsolutePath()));
            }
            final Principal principal = new KerberosPrincipal(spn, KerberosPrincipal.KRB_NT_SRV_INST);
            Set<Principal> principals = new HashSet<>();
            principals.add(principal);

            final Subject subject = new Subject(false, principals, new HashSet<>(), new HashSet<>());

            ctx = new LoginContext(config.getContextName(), subject, null, getJaasKrb5TicketCfg(spn));
            ctx.login();

            final Krb5TicketValidateAction validateAction = new Krb5TicketValidateAction(ticket, spn);
            final String username = Subject.doAs(subject, validateAction);
            return username;
        } catch (java.security.PrivilegedActionException | LoginException e) {
            LOG.fatal(spn, e);
        } finally {
            try {
                if (ctx != null) {
                    ctx.logout();
                }
            } catch (LoginException e2) {
                LOG.fatal(spn, e2);
            }
        }

        return FAILED;
    }

    private class Krb5TicketValidateAction implements PrivilegedExceptionAction<String> {

        private static final String SPNEGO_OID = "1.3.6.1.5.5.2";

        private final byte[] ticket;
        private final String spn;

        public Krb5TicketValidateAction(final byte[] ticket, final String spn) {
            this.ticket = ticket;
            this.spn = spn;
        }

        @Override
        public String run() throws GSSException {
            final Oid spnegoOid = new Oid(SPNEGO_OID);
            final GSSManager gssmgr = GSSManager.getInstance();
            final GSSName serviceName = gssmgr.createName(
                    spn,
                    GSSName.NT_USER_NAME
            );
            final GSSCredential serviceCredentials = gssmgr.createCredential(
                    serviceName,
                    GSSCredential.INDEFINITE_LIFETIME,
                    spnegoOid, GSSCredential.ACCEPT_ONLY
            );
            final GSSContext gssContext = gssmgr.createContext(serviceCredentials);
            try {
                gssContext.acceptSecContext(ticket, 0, ticket.length);
                return gssContext.getSrcName().toString();
            } finally {
                gssContext.dispose();
            }
        }
    }

    private static String normalize(final String data) {
        if (data.isEmpty()) {
            return data;
        }
        if (data.endsWith(".")) {
            return normalize(data.substring(0, data.length() - 1));
        }
        return data;
    }

    private static String recurseResolveToA(final Nameserver ns, final Set<String> checked, final String host) throws NamingException {
        if (checked.contains(host)) {
            throw new NamingException(String.format("Recursive Name Lookup: %s", checked));
        }
        final String[] clookup = ns.lookup(host, "cname");
        if (clookup.length != 0) {
            checked.add(host);
            return recurseResolveToA(ns, checked, normalize(clookup[0]));
        }

        return host;
    }

    public static String resolveServerName(final String serverName) {
        try {
            return recurseResolveToA(new Nameserver(), new HashSet<>(), serverName);
        } catch (NamingException ex) {
            LOG.error(String.format("Cannot Resolve %s - %s", serverName, ex.getMessage()), ex);
            return null;
        }
    }

    public static String extractTicket(final String _ticket) {
        final String[] ticketParts = _ticket.split(" ");
        if ((ticketParts.length != 2) || (!Krb5.NEGOTIATE.equals(ticketParts[0]))) {
            LOG.error(String.format("Invalid KRB5 Ticket: %s", _ticket));
            return null;
        }
        return ticketParts[1];
    }
}

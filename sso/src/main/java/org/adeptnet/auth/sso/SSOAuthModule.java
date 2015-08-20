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

import org.adeptnet.auth.sso.common.SSOCredentials;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.config.ServerAuthContext;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.ServletRequestWrapper;
import javax.servlet.ServletResponseWrapper;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;
import javax.servlet.http.HttpSession;
import org.adeptnet.auth.kerberos.Krb5;
import org.adeptnet.auth.saml.SAMLClient;
import org.adeptnet.auth.saml.SAMLException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.adeptnet.auth.sso.common.Krb5Credentials;
import org.adeptnet.auth.sso.common.SAMLCredentials;
import org.adeptnet.auth.sso.common.SSOCallback;

/**
 *
 * @author Francois Steyn - Adept Internet (PTY) LTD (francois.s@adept.co.za)
 */
public class SSOAuthModule implements ServerAuthModule, ServerAuthContext, CallbackHandler {

    private static final Logger LOG = Logger.getLogger(SSOAuthModule.class.getName());

    private static final Class<?>[] SUPPORTED_MESSAGE_TYPES = new Class<?>[]{HttpServletRequest.class, HttpServletResponse.class};
    private static final String IS_MANDATORY_INFO_KEY = "javax.security.auth.message.MessagePolicy.isMandatory";
    private static final String SESSION_SAVED_SUBJECT_KEY = "ServerAuthModule.SAVED.SUBJECT";
    private static final String PARAM_JAAS_CONTEXT_PARAM = "jaas-context";
    private static final String PARAM_LOGIN_PAGE = "login-page";
    private static final String PARAM_LOGIN_ERROR = "login-error-page";
    //private static final String PARAM_DEFAULT_PAGE = "default-page";
    private static final String J_SECURITY_CHECK = "/j_security_check";
    private static final String J_SECURITY_LOGOUT = "/j_security_logout";

    private CallbackHandler handler;
    private String _jaasCtx;
    private String _loginPage;
    //private String _defaultPage;
    private String _loginErrorPage;
    private SSOCredentials credentials;
    private Map<?, ?> options;

    private String getStringOption(final java.util.Map<?, ?> options, final String name) throws AuthException {
        final Object val = options.get(name);
        if (val instanceof String) {
            return (String) val;
        } else {
            throw new AuthException(String.format("'%s' must be supplied as a property in the provider-config in the domain.xml file!", name));
        }
    }

    private String getLoginPage() throws AuthException {
        if (_loginPage == null) {
            _loginPage = getStringOption(options, PARAM_LOGIN_PAGE);
        }
        return _loginPage;
    }

    private String getLoginErrorPage() throws AuthException {
        if (_loginErrorPage == null) {
            _loginErrorPage = getStringOption(options, PARAM_LOGIN_ERROR);
        }
        return _loginErrorPage;
    }

    private String getJaasCtx() throws AuthException {
        if (_jaasCtx == null) {
            _jaasCtx = getStringOption(options, PARAM_JAAS_CONTEXT_PARAM);
        }
        return _jaasCtx;
    }

    @Override
    public void initialize(final MessagePolicy requestPolicy, final MessagePolicy responsePolicy, final CallbackHandler handler, final Map options) throws AuthException {
        if (LOG.isLoggable(Level.FINER)) {
            LOG.finer("initialize");
        }
        if (options == null) {
            throw new AuthException("options is null");
        }
        if (handler == null) {
            throw new AuthException("handler is null");
        }
        this.handler = handler;
        this.options = options;
        getLoginPage();
        getJaasCtx();
    }

    @Override
    public Class[] getSupportedMessageTypes() {
        if (LOG.isLoggable(Level.FINER)) {
            LOG.finer("getSupportedMessageTypes");
        }
        return SUPPORTED_MESSAGE_TYPES;
    }

    private boolean isMandatory(final MessageInfo messageInfo) {
        return Boolean.valueOf((String) messageInfo.getMap().get(IS_MANDATORY_INFO_KEY));
    }

    private AuthStatus redirectToErrorScreen(final HttpServletRequest request, final HttpServletResponse response, final String messageText, final String errorText) throws AuthException {
        if (LOG.isLoggable(Level.FINER)) {
            LOG.finer(String.format("redirectToErrorScreen messageText=%s errorText=%s", messageText, errorText));
        }
        request.setAttribute("messageText", messageText);
        request.setAttribute("errorText", errorText);
        final RequestDispatcher rDispatcher = request.getRequestDispatcher(getLoginErrorPage());
        try {
            rDispatcher.forward(request, response);
        } catch (ServletException | IOException ex) {
            LOG.log(Level.SEVERE, ex.getMessage(), ex);
        }
        return AuthStatus.SEND_FAILURE;
    }

    private AuthStatus redirectToErrorScreen(final HttpServletRequest request, final HttpServletResponse response, final Throwable throwable) throws AuthException {
        LOG.log(Level.SEVERE, throwable.getMessage(), throwable);
        return redirectToErrorScreen(request, response, throwable.getClass().getName(), throwable.getMessage());
    }

    private void doSSOHeader(final HttpServletRequest request, final HttpServletResponse response) {
        if (request.getHeader(Krb5.AUTHORIZATION) == null) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setHeader(Krb5.WWW_AUTHENTICATE, Krb5.NEGOTIATE);
        }
        request.setAttribute("doSSO", request.getRequestURI());
    }

    private AuthStatus redirectToLoginScreen(final HttpServletRequest request, final HttpServletResponse response) throws AuthException {
        doSSOHeader(request, response);
        final RequestDispatcher rDispatcher = request.getRequestDispatcher(getLoginPage());
        try {
            rDispatcher.forward(request, response);
        } catch (ServletException | IOException ex) {
            LOG.log(Level.SEVERE, ex.getMessage(), ex);
            final AuthException ae = new AuthException(String.format("Redirect to loginPage: %s", getLoginPage()));
            ae.initCause(ex);
            throw ae;
        }

        return AuthStatus.SEND_CONTINUE;
    }

    private AuthStatus logoutSession(final HttpServletRequest request, final HttpServletResponse response, final Subject clientSubject) throws AuthException {
        try {
            request.logout();
            if (LOG.isLoggable(Level.FINE)) {
                LOG.log(Level.FINE, String.format("validateRequest %s ==> logout redirect ", request.getRequestURI()));
            }
            try {
                final HttpSession session = request.getSession(false);
                if (session != null) {
                    session.invalidate();
                }
            } catch (Throwable e) {
                LOG.log(Level.WARNING, "Session was already invalid ", e);
            }
            return redirectToLoginScreen(request, response);
        } catch (ServletException ex) {
            return redirectToErrorScreen(request, response, ex);
        }
    }

    private boolean restoreSavedCredentials(final Subject clientSubject, final HttpSession session, final HttpServletRequest request, final HttpServletResponse response) {
        final Subject savedClientSubject = (session.getAttribute(SESSION_SAVED_SUBJECT_KEY) instanceof Subject ? (Subject) session.getAttribute(SESSION_SAVED_SUBJECT_KEY) : null); // NOPMD , long names
        if (savedClientSubject != null) {
            clientSubject.getPrincipals().addAll(savedClientSubject.getPrincipals());
            clientSubject.getPublicCredentials().addAll(savedClientSubject.getPublicCredentials());
            clientSubject.getPrivateCredentials().addAll(savedClientSubject.getPrivateCredentials());
            if (LOG.isLoggable(Level.FINE)) {
                LOG.log(Level.FINE, "CustomFormAuthModule validateRequest {0} ==> restored pricipals ==> SUCCESS  {1}\n\n\n\n", new Object[]{request.getRequestURI(), response.getStatus()});
            }
            return true;
        }
        return false;
    }

    private String getOrigin(final HttpServletRequest request) {
        final StringBuilder stringBuilder = new StringBuilder();
        for (final java.util.Enumeration<String> vias = request.getHeaders("Via"); vias.hasMoreElements();) {
            if (stringBuilder.length() > 0) {
                stringBuilder.append(", ");
            }
            stringBuilder.append("Via:").append(vias.nextElement());
        }
        for (final java.util.Enumeration<String> vias = request.getHeaders("x-forwarded-for"); vias.hasMoreElements();) {
            if (stringBuilder.length() > 0) {
                stringBuilder.append(", ");
            }
            stringBuilder.append("x-forwarded-for:").append(vias.nextElement());
        }
        return String.format("%s:%s %s", request.getContextPath(), request.getRemoteAddr(), stringBuilder.toString());
    }

    private boolean isLoginPage(final String uri) throws AuthException {
        return uri.endsWith(getLoginPage());
    }

    private boolean isRedirectUrl(final String uri) throws AuthException {
        return (isLoginPage(uri)) || (uri.endsWith(J_SECURITY_CHECK)) || (uri.endsWith(J_SECURITY_LOGOUT));
    }

    private String getRedirectUrl(final String uri) throws AuthException {
        if (isLoginPage(uri)) {
            return uri.substring(0, uri.length() - getLoginPage().length());
        }
        if (uri.endsWith(J_SECURITY_CHECK)) {
            return uri.substring(0, uri.length() - J_SECURITY_CHECK.length());
        }
        if (uri.endsWith(J_SECURITY_LOGOUT)) {
            return uri.substring(0, uri.length() - J_SECURITY_LOGOUT.length());
        }
        return uri;
    }

    private AuthStatus doRedirect(final HttpServletRequest request, final HttpServletResponse response, final String url) throws AuthException {
        try {
            if (LOG.isLoggable(Level.FINER)) {
                LOG.finer(String.format("sendRedirect: %s", url));
            }
            response.sendRedirect(url);
            return AuthStatus.SEND_CONTINUE;
        } catch (IOException ex) {
            return redirectToErrorScreen(request, response, ex);
        }
    }

    @Override
    public AuthStatus validateRequest(final MessageInfo messageInfo, final Subject clientSubject, final Subject serviceSubject) throws AuthException {
        try {
            final HttpServletRequest request = (HttpServletRequest) messageInfo.getRequestMessage();
            final HttpServletResponse response = (HttpServletResponse) messageInfo.getResponseMessage();

            if (LOG.isLoggable(Level.FINE)) {
                LOG.fine(String.format("validateRequest: %s - %s", handler, request.getRequestURI()));
            }

            final String auth = request.getHeader(Krb5.AUTHORIZATION);
            if (request.getRequestURI().endsWith(J_SECURITY_LOGOUT) && (auth == null)) {
                return logoutSession(request, response, clientSubject);
            }

            final HttpSession session = request.getSession(true);
            if ((session != null) && (restoreSavedCredentials(clientSubject, session, request, response))) {
                if (isRedirectUrl(request.getRequestURI())) {
                    return doRedirect(request, response, request.getContextPath());
                } else {
                    return AuthStatus.SUCCESS;
                }
            }

            if (!isMandatory(messageInfo) && !request.getRequestURI().endsWith(J_SECURITY_CHECK) && (auth == null)) {
                if (LOG.isLoggable(Level.FINE)) {
                    LOG.log(Level.FINE, "CustomFormAuthModule validateRequest notMandatory {0} ==> SUCCESS {1}\n\n\n\n", new Object[]{request.getRequestURI(), response.getStatus()});
                }
                if (isLoginPage(request.getRequestURI())) {
                    doSSOHeader(request, response);
                }
                return AuthStatus.SUCCESS;
            }

            final String fragment = request.getParameter("j_fragment");
            final String url = request.getParameter("j_url");
            final String saml = request.getParameter(SAMLClient.SAML_RESPONSE);
            final String redirectUrl;
            if ((auth != null) && (auth.startsWith(String.format("%s ", Krb5.NEGOTIATE)))) {
                credentials = new Krb5Credentials(request.getServerName(), auth.split(" ")[1], getOrigin(request));
                if (isRedirectUrl(request.getRequestURI())) {
                    redirectUrl = request.getContextPath();
                } else {
                    redirectUrl = null;
                }
            } else if (saml != null) {
                credentials = new SAMLCredentials(request.getServerName(), "GET".equalsIgnoreCase(request.getMethod()), saml, request.getQueryString(), getOrigin(request));
                final String relayState = request.getParameter(SAMLClient.SAML_RELAYSTATE);
                redirectUrl = relayState == null ? null : new String(Base64.getDecoder().decode(relayState.getBytes()));
            } else if (url != null) {
                final String relayState = new String(Base64.getEncoder().encode(String.format("%s%s", getRedirectUrl(url), fragment).getBytes()));
                try {
                    Common.getInstance(options).doSAMLRedirect(request, response, relayState);
                } catch (SAMLException | MessageEncodingException ex) {
                    return redirectToErrorScreen(request, response, ex);
                }
                return AuthStatus.SEND_CONTINUE;
            } else {
                return redirectToLoginScreen(request, response);
            }

            try {
                final LoginContext lc = new LoginContext(getJaasCtx(), clientSubject, this);
                lc.login();
                session.setAttribute(SESSION_SAVED_SUBJECT_KEY, clientSubject);// Save the Subject...
            } catch (LoginException ex) {
                return redirectToErrorScreen(request, response, ex);
            }
            if (redirectUrl == null) {
                return AuthStatus.SUCCESS;
            } else {
                return doRedirect(request, response, redirectUrl);
            }
        } catch (Throwable ex) {
            LOG.log(Level.SEVERE, ex.getMessage(), ex);
            throw ex;
        }
    }

    @Override
    public AuthStatus secureResponse(final MessageInfo messageInfo, final Subject serviceSubject) throws AuthException {
        if (LOG.isLoggable(Level.FINER)) {
            LOG.finer("secureResponse");
        }
        boolean wrapped = false;
        HttpServletRequest r = (HttpServletRequest) messageInfo.getRequestMessage();
        while (r != null && r instanceof HttpServletRequestWrapper) {
            r = (HttpServletRequest) ((ServletRequestWrapper) r).getRequest();
            wrapped = true;
        }
        if (wrapped) {
            messageInfo.setRequestMessage(r);
        }
        wrapped = false;
        HttpServletResponse s = (HttpServletResponse) messageInfo.getResponseMessage();
        while (s != null && s instanceof HttpServletResponseWrapper) {
            s = (HttpServletResponse) ((ServletResponseWrapper) s).getResponse();
            wrapped = true;
        }
        if (wrapped) {
            messageInfo.setResponseMessage(s);
        }

        return AuthStatus.SEND_SUCCESS;
    }

    @Override
    public void cleanSubject(final MessageInfo messageInfo, final Subject subject) throws AuthException {
        if (LOG.isLoggable(Level.FINER)) {
            LOG.finer("cleanSubject");
        }
        if (subject == null) {
            return;
        }
        final Object o = messageInfo.getRequestMessage();
        if ((o != null) && (o instanceof HttpServletRequest)) {
            final HttpServletRequest request = (HttpServletRequest) o;
            final HttpSession session = request.getSession(false);
            if (session != null) {
                if (LOG.isLoggable(Level.FINER)) {
                    LOG.finer("session.removeAttribute");
                }
                session.removeAttribute(SESSION_SAVED_SUBJECT_KEY);
            }
        }
        try {
            if (LOG.isLoggable(Level.FINER)) {
                LOG.finer("lc.logout");
            }
            final LoginContext lc = new LoginContext(getJaasCtx(), subject, this);
            lc.logout();
        } catch (LoginException ex) {
            LOG.log(Level.SEVERE, ex.getMessage(), ex);
        }

        if (LOG.isLoggable(Level.FINER)) {
            LOG.finer("clear subject");
        }
        subject.getPrincipals().clear();
        subject.getPrivateCredentials().clear();
        subject.getPublicCredentials().clear();
    }

    @Override
    public void handle(final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        if (LOG.isLoggable(Level.FINER)) {
            LOG.finer(String.format("handle %d", callbacks.length));
        }
        final List<Callback> toHandle = new ArrayList<>();
        for (final Callback cb : callbacks) {
            if (LOG.isLoggable(Level.FINER)) {
                LOG.finer(String.format("handle %s: %s", cb.getClass(), cb));
            }
            if (cb instanceof SSOCallback) {
                final SSOCallback sso = (SSOCallback) cb;
                sso.setCredentials(credentials);
                continue;
            }
            toHandle.add(cb);
        }
        if ((handler != null) && (!toHandle.isEmpty())) {
            try {
                handler.handle(toHandle.toArray(new Callback[toHandle.size()]));
            } catch (IOException | UnsupportedCallbackException ex) {
                LOG.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }
    }

}

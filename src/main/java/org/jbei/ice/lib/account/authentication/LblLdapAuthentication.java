package org.jbei.ice.lib.account.authentication;

import org.jbei.ice.lib.account.AccountController;
import org.jbei.ice.lib.common.logging.Logger;
import org.jbei.ice.storage.DAOFactory;
import org.jbei.ice.storage.model.Account;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Hashtable;


/**
 * Authentication for LBL's LDAP system. Uses local authentication as a fallback
 * if the account does not exist with LBL LDAP directory
 *
 * @author Hector Plahar
 */
public class LblLdapAuthentication implements IAuthentication {

    protected DirContext dirContext;
    protected String searchURL;
    protected String authenticationURL;
    protected String ldapProvider;
    protected String ldapUser;
    protected String ldapPass;
    protected boolean initialized;

    public boolean authenticated;
    public String givenName;
    public String sirName;
    public String email;
    public String organization;
    public String description;

    public LblLdapAuthentication() {
        initialize();
        givenName = "";
        sirName = "";
        email = "";
        organization = "";
        description = "";
    }

    @Override
    public String authenticates(String loginId, String password) throws AuthenticationException {
        if (loginId == null || password == null || loginId.isEmpty() || password.isEmpty()) {
            throw new AuthenticationException("Username and Password are mandatory!");
        }

        loginId = loginId.toLowerCase().trim();
        String authenticatedEmail;
        //authenticatedEmail = authenticateWithLDAP(loginId, password);
        if (true) {
            try {
                authenticatedEmail = authenticateWithLDAP(loginId, password);
                if (authenticatedEmail == null) {
                    return null;
                }
            } catch (AuthenticationException ae) {
                return null;
            }

            Account account = checkCreateAccount(authenticatedEmail);
            if (account == null)
                return null;
            return account.getEmail();
        } else {
            LocalAuthentication localBackend = new LocalAuthentication();
            return localBackend.authenticates(loginId, password);
        }
    }

    /**
     * Intended to be called when the credentials successfully authenticate with ldap.
     * Ensures an account exists with the login specified in the parameter which also belongs to the
     * LBL/JBEI group.
     * <p/>
     * Since LBL's LDAP mechanism handles authentication, no password information is
     * managed
     *
     * @param loginId unique login identifier
     */
    private Account checkCreateAccount(String loginId) throws AuthenticationException {
        AccountController retriever = new AccountController();
        Account account = retriever.getByEmail(loginId);

        if (account == null) {
            account = new Account();
            Date currentTime = Calendar.getInstance().getTime();
            account.setCreationTime(currentTime);
            account.setEmail(getEmail().toLowerCase());
            account.setFirstName(getGivenName());
            account.setLastName(getSirName());
            account.setDescription(getDescription());
            account.setPassword("");
            account.setInitials("");
            account.setIp("");
            account.setInstitution("Lawrence Berkeley Laboratory");
            account.setModificationTime(currentTime);
            account = DAOFactory.getAccountDAO().create(account);
        }

        return account;
    }

    /**
     * Authenticate user to the ldap server.
     *
     * @param userName
     * @param passWord
     * @return valid email if successfully authenticated, null otherwise
     */
    public String authenticateWithLDAP(String userName, String passWord) throws AuthenticationException {
        DirContext authContext = null;

        try {
            authenticated = false;
            String employeeNumber = "";

            //has to look up employee number for binding
            int idx = userName.indexOf("@biosustain.dtu.dk");
            if (idx > 0)
                userName = userName.substring(0, idx);
            //String filter = "(uid=" + userName + ")";
            String filter = String.format("(&(sAMAccountName=%s)(memberOf=CN=NNFCB-CFB-All-28860,ou=SecurityGroups,ou=NNFCB,ou=DTUBasen,dc=win,dc=dtu,dc=dk))", userName);
            SearchControls cons = new SearchControls();
            cons.setSearchScope(SearchControls.SUBTREE_SCOPE);
            cons.setCountLimit(0);

            if (dirContext == null) {
                dirContext = getContext();
            }

            String LDAP_QUERY = "ou=DTUBaseUsers,dc=win,dc=dtu,dc=dk";
            SearchResult searchResult = dirContext.search(LDAP_QUERY, filter, cons).nextElement();

            Attributes attributes = searchResult.getAttributes();
            //employeeNumber = (String) attributes.get("lblempnum").get();

            if (attributes.get("givenName") != null) {
                givenName = (String) attributes.get("givenName").get();
            }
            if (attributes.get("sn") != null) {
                sirName = (String) attributes.get("sn").get();
            }
            if (attributes.get("mail") != null) {
                email = (String) attributes.get("mail").get();
            }
            email = email.toLowerCase();
            /** organization = "Lawrence Berkeley Laboratory";
            if (attributes.get("description") != null) {
                description = (String) attributes.get("description").get();
            } **/
            authContext = getAuthenticatedContext(userName, passWord);

            authContext.close();
            dirContext.close(); //because authentication should be the last step
        } catch (NamingException e) {
            throw new AuthenticationException("Got LDAP NamingException", e);
        } finally {
            if (authContext != null) {
                try {
                    authContext.close();
                } catch (NamingException e) {
                    throw new AuthenticationException("Got LDAP NamingException", e);
                }
            }
            try {
                dirContext.close();
            } catch (NamingException e) {
                throw new AuthenticationException("Got LDAP NamingException", e);
            }
        }

        return email;
    }

    public boolean isAuthenticated() {
        return authenticated;
    }

    public String getGivenName() {
        return givenName;
    }

    public String getSirName() {
        return sirName;
    }

    public String getEmail() {
        return email;
    }

    public String getOrganization() {
        return organization;
    }

    public String getDescription() {
        return description;
    }

    /**
     * Get unauthenticated ldap context.
     *
     * @return {@link javax.naming.directory.DirContext} object.
     * @throws javax.naming.NamingException
     */
    protected DirContext getContext() throws NamingException {
        Hashtable<String, String> env = new Hashtable<String, String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put("com.sun.jndi.ldap.connect.pool", "true");
        env.put("com.sun.jndi.ldap.connect.pool.timeout", "10000");

        env.put("com.sun.jndi.ldap.read.timeout", "5000");
        env.put("com.sun.jndi.ldap.connect.timeout", "10000");

        env.put(Context.PROVIDER_URL, ldapProvider);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");


        env.put(Context.SECURITY_PRINCIPAL, ldapUser);

        env.put(Context.SECURITY_CREDENTIALS,ldapPass);

        LdapContext ctx = null;
        try {
            ctx = new InitialLdapContext(env, null);
        } catch (NamingException e) {
            e.printStackTrace();
            throw e;
        }

        return ctx;
    }

    /**
     * Get authenticated context from the ldap server. Failure means bad user or password.
     *
     * @param passWord
     * @return {@link javax.naming.directory.DirContext} object.
     * @throws javax.naming.NamingException
     */
    protected DirContext getAuthenticatedContext(String userName, String passWord) throws NamingException {
        String baseDN = "dc=win,dc=dtu,dc=dk";
        Hashtable<String, String> env = new Hashtable<String, String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put("com.sun.jndi.ldap.connect.pool", "true");
        env.put("com.sun.jndi.ldap.connect.pool.timeout", "10000");

        env.put("com.sun.jndi.ldap.read.timeout", "5000");
        env.put("com.sun.jndi.ldap.connect.timeout", "10000");

        env.put(Context.PROVIDER_URL, ldapProvider);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, String.format("%s@win", userName));
        env.put(Context.SECURITY_CREDENTIALS, passWord);

        LdapContext result = new InitialLdapContext(env, null);

        return result;
    }

    private void initialize() {
        if (!initialized) {
            ldapProvider = System.getenv("LDAP_PROVIDER");
            ldapUser = System.getenv("LDAP_USER");
            ldapPass = System.getenv("LDAP_PASS");
            initialized = true;
        }
    }
}

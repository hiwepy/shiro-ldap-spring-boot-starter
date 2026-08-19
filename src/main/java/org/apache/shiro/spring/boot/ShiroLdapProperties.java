/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.shiro.spring.boot;

import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(ShiroLdapProperties.PREFIX)
/**
 * Configuration properties.
 * <p>Binds to the application property prefix and provides
 * customizable settings.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class ShiroLdapProperties {

	public static final String PREFIX = "shiro.ldap";
	
	/**
	 * Enable Shiro Ldap.
	 */
	private boolean enabled = false;
	
	 // --- private members ----
    /** A flag indicating if we are using SSL or not, default value is false */
    private boolean useSsl = false;

    /** The selected LDAP port */
    private int ldapPort;

    /** the remote LDAP host */
    private String ldapHost;

    /** a valid Dn to authenticate the user */
    private String name;

    /** user's credentials ( current implementation supports password only); it must be a non-null value */
    private String credentials;

    /** an array of cipher suites which are enabled, if set, will be used while initializing the SSL context */
    private String[] enabledCipherSuites;

    /** name of the protocol used for creating SSL context, default value is "TLS" */
    private String sslProtocol = LdapConnectionConfig.DEFAULT_SSL_PROTOCOL;

	/**
	 * Returns the enabled.
	 *
	 * @return the enabled
	 */
	public boolean isEnabled() {
		return enabled;
	}

	/**
	 * Sets the enabled.
	 *
	 * @param enabled the enabled
	 */
	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	/**
	 * Returns the use ssl.
	 *
	 * @return the use ssl
	 */
	public boolean isUseSsl() {
		return useSsl;
	}

	/**
	 * Sets the use ssl.
	 *
	 * @param useSsl the use ssl
	 */
	public void setUseSsl(boolean useSsl) {
		this.useSsl = useSsl;
	}

	/**
	 * Returns the ldap port.
	 *
	 * @return the ldap port
	 */
	public int getLdapPort() {
		return ldapPort;
	}

	/**
	 * Sets the ldap port.
	 *
	 * @param ldapPort the ldap port
	 */
	public void setLdapPort(int ldapPort) {
		this.ldapPort = ldapPort;
	}

	/**
	 * Returns the ldap host.
	 *
	 * @return the ldap host
	 */
	public String getLdapHost() {
		return ldapHost;
	}

	/**
	 * Sets the ldap host.
	 *
	 * @param ldapHost the ldap host
	 */
	public void setLdapHost(String ldapHost) {
		this.ldapHost = ldapHost;
	}

	/**
	 * Returns the name.
	 *
	 * @return the name
	 */
	public String getName() {
		return name;
	}

	/**
	 * Sets the name.
	 *
	 * @param name the name
	 */
	public void setName(String name) {
		this.name = name;
	}

	/**
	 * Returns the credentials.
	 *
	 * @return the credentials
	 */
	public String getCredentials() {
		return credentials;
	}

	/**
	 * Sets the credentials.
	 *
	 * @param credentials the credentials
	 */
	public void setCredentials(String credentials) {
		this.credentials = credentials;
	}

	/**
	 * Returns the enabled cipher suites.
	 *
	 * @return the enabled cipher suites
	 */
	public String[] getEnabledCipherSuites() {
		return enabledCipherSuites;
	}

	/**
	 * Sets the enabled cipher suites.
	 *
	 * @param enabledCipherSuites the enabled cipher suites
	 */
	public void setEnabledCipherSuites(String[] enabledCipherSuites) {
		this.enabledCipherSuites = enabledCipherSuites;
	}

	/**
	 * Returns the ssl protocol.
	 *
	 * @return the ssl protocol
	 */
	public String getSslProtocol() {
		return sslProtocol;
	}

	/**
	 * Sets the ssl protocol.
	 *
	 * @param sslProtocol the ssl protocol
	 */
	public void setSslProtocol(String sslProtocol) {
		this.sslProtocol = sslProtocol;
	}
    
}


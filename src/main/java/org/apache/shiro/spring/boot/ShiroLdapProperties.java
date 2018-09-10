/*
 * Copyright (c) 2017, vindell (https://github.com/vindell).
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

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public boolean isUseSsl() {
		return useSsl;
	}

	public void setUseSsl(boolean useSsl) {
		this.useSsl = useSsl;
	}

	public int getLdapPort() {
		return ldapPort;
	}

	public void setLdapPort(int ldapPort) {
		this.ldapPort = ldapPort;
	}

	public String getLdapHost() {
		return ldapHost;
	}

	public void setLdapHost(String ldapHost) {
		this.ldapHost = ldapHost;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getCredentials() {
		return credentials;
	}

	public void setCredentials(String credentials) {
		this.credentials = credentials;
	}

	public String[] getEnabledCipherSuites() {
		return enabledCipherSuites;
	}

	public void setEnabledCipherSuites(String[] enabledCipherSuites) {
		this.enabledCipherSuites = enabledCipherSuites;
	}

	public String getSslProtocol() {
		return sslProtocol;
	}

	public void setSslProtocol(String sslProtocol) {
		this.sslProtocol = sslProtocol;
	}
    
}


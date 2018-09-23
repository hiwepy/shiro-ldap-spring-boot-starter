/*
 * Copyright (c) 2018, vindell (https://github.com/vindell).
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
package org.apache.shiro.spring.boot.ldap;

import java.util.Collection;
import java.util.Set;

import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.shared.ldap.model.cursor.EntryCursor;
import org.apache.directory.shared.ldap.model.entry.Attribute;
import org.apache.directory.shared.ldap.model.entry.Entry;
import org.apache.directory.shared.ldap.model.message.SearchScope;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.biz.authz.principal.ShiroPrincipal;
import org.apache.shiro.biz.authz.principal.ShiroPrincipalRepository;
import org.apache.shiro.biz.utils.StringUtils;
import org.apache.shiro.spring.boot.ShiroLdapProperties;
import org.apache.shiro.spring.boot.ldap.exception.IncorrectLdapException;
import org.apache.shiro.spring.boot.ldap.token.LdapLoginToken;
import org.apache.shiro.spring.boot.ldap.utils.LdapConnectionUtils;

import com.google.common.collect.Sets;

/**
 * Kisso Token Principal Repository
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */
public class LdapPrincipalRepository implements ShiroPrincipalRepository<LdapPrincipal> {
	
	private static final String USER_GROUP = "dc=users,DC=ITS";  
	private ShiroLdapProperties properties;
	
	@Override
	public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		
		LdapLoginToken ldapToken = (LdapLoginToken) token;
		
		StringBuilder searchQuery = new StringBuilder();  
        if (StringUtils.hasText(ldapToken.getUsername())) {  
            searchQuery.append("(uid=").append(ldapToken.getUsername()).append(")");  
        } else {
            searchQuery.append("(uid=*)");  
        } 
        ShiroPrincipal principal = new LdapPrincipal(); 
        LdapConnection connection = LdapConnectionUtils.openConnection(properties.getLdapHost(), properties.getLdapPort(), properties.getName(), properties.getCredentials());
        try {  
            EntryCursor search = connection.search(USER_GROUP, searchQuery.toString(), SearchScope.ONELEVEL, "*");  
            while (search.next()) {  
            	
                Entry entry = search.get();  
                Collection<Attribute> attributes = entry.getAttributes();  
                for (Attribute attribute : attributes) {  
                    String key = attribute.getId();  
                    if ("uid".equalsIgnoreCase(key)) {  
                    	principal.setUserid(attribute.getString());
                    } else if ("ukey".equalsIgnoreCase(key)) {  
                        principal.setUserkey(attribute.getString());
                    } else if ("roles".equalsIgnoreCase(key)) {  
                        principal.setRoles(Sets.newHashSet(StringUtils.tokenizeToStringArray(attribute.getString())));
                    } else if ("perms".equalsIgnoreCase(key)) {  
                    	principal.setPerms(Sets.newHashSet(StringUtils.tokenizeToStringArray(attribute.getString())));
                    } else if ("sn".equalsIgnoreCase(key)) {  
                        principal.setUsername(attribute.getString());
                    } else if ("cn".equalsIgnoreCase(key)) {  
//                      user.setFirstName(attribute.getString().substring(0,  
//                              attribute.getString().indexOf(" ")));  
                    }  
                }  
            }  
  
            search.close();  
  
            return new SimpleAuthenticationInfo(principal, ldapToken, "kisso");
        } catch (Exception e) {  
            throw new IncorrectLdapException("LDAP connection search failure", e);  
        } finally {
        	LdapConnectionUtils.closeConnection(connection);  
		} 
        
	}

	@Override
	public Set<String> getRoles(LdapPrincipal principal) {
		return principal.getRoles();
	}

	@Override
	public Set<String> getRoles(Set<LdapPrincipal> principals) {
		Set<String> sets = Sets.newHashSet();
		for (ShiroPrincipal principal : principals) {
			sets.addAll(principal.getRoles());
		}
		return sets;
	}

	@Override
	public Set<String> getPermissions(LdapPrincipal principal) {
		return Sets.newHashSet(principal.getPerms());
	}

	@Override
	public Set<String> getPermissions(Set<LdapPrincipal> principals) {
		Set<String> sets = Sets.newHashSet();
		for (ShiroPrincipal principal : principals) {
			sets.addAll(principal.getPerms());
		}
		return sets;
	}
	
	@Override
	public void doLock(LdapPrincipal principal) {
		// do nothing
	}
	
}

package org.apache.shiro.spring.boot.ldap.token;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("LdapLoginToken Tests")
class LdapLoginTokenTest {

    @Test
    @DisplayName("Default constructor creates non-null instance")
    void testDefaultConstructor() {
        LdapLoginToken token = new LdapLoginToken();
        assertThat(token).isNotNull();
        assertThat(token).isInstanceOf(org.apache.shiro.authc.AuthenticationToken.class);
    }

    @Test
    @DisplayName("Token extends DefaultAuthenticationToken")
    void testInheritance() {
        LdapLoginToken token = new LdapLoginToken();
        assertThat(token).isInstanceOf(org.apache.shiro.biz.authc.token.DefaultAuthenticationToken.class);
    }
}

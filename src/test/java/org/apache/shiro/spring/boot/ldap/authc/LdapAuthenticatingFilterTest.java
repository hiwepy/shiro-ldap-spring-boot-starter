package org.apache.shiro.spring.boot.ldap.authc;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("LdapAuthenticatingFilter Tests")
class LdapAuthenticatingFilterTest {

    @Test
    @DisplayName("Instance can be created via constructor")
    void testInstantiation() {
        LdapAuthenticatingFilter instance = new LdapAuthenticatingFilter();
        assertThat(instance).isNotNull();
        assertThat(instance).isInstanceOf(org.apache.shiro.biz.web.filter.authc.AbstractTrustableAuthenticatingFilter.class);
    }

    @Test
    @DisplayName("Filter extends AbstractTrustableAuthenticatingFilter")
    void testInheritance() {
        assertThat(org.apache.shiro.biz.web.filter.authc.AbstractTrustableAuthenticatingFilter.class
                .isAssignableFrom(LdapAuthenticatingFilter.class)).isTrue();
    }
}

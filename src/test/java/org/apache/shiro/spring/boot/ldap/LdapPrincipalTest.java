package org.apache.shiro.spring.boot.ldap;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("LdapPrincipal Tests")
class LdapPrincipalTest {

    @Test
    @DisplayName("Instance can be created via constructor")
    void testInstantiation() {
        LdapPrincipal instance = new LdapPrincipal();
        assertThat(instance).isNotNull();
        assertThat(instance).isInstanceOf(org.apache.shiro.biz.authz.principal.ShiroPrincipal.class);
    }

    @Test
    @DisplayName("Can set and get userid")
    void testUserid() {
        LdapPrincipal p = new LdapPrincipal();
        p.setUserid("uid123");
        assertThat(p.getUserid()).isEqualTo("uid123");
    }

    @Test
    @DisplayName("Can set and get username")
    void testUsername() {
        LdapPrincipal p = new LdapPrincipal();
        p.setUsername("testuser");
        assertThat(p.getUsername()).isEqualTo("testuser");
    }

    @Test
    @DisplayName("Can set and get userkey")
    void testUserkey() {
        LdapPrincipal p = new LdapPrincipal();
        p.setUserkey("key123");
        assertThat(p.getUserkey()).isEqualTo("key123");
    }
}

package org.apache.shiro.spring.boot.ldap.realm;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("LdapStatefulAuthorizingRealm Tests")
class LdapStatefulAuthorizingRealmTest {

    @Test
    @DisplayName("Constructor creates non-null instance")
    void testConstructor() {
        LdapStatefulAuthorizingRealm realm = new LdapStatefulAuthorizingRealm();
        assertThat(realm).isNotNull();
    }

    @Test
    @DisplayName("getAuthenticationTokenClass returns LdapLoginToken")
    void testGetAuthenticationTokenClass() {
        LdapStatefulAuthorizingRealm realm = new LdapStatefulAuthorizingRealm();
        assertThat(realm.getAuthenticationTokenClass()).isEqualTo(
                org.apache.shiro.spring.boot.ldap.token.LdapLoginToken.class);
    }
}

package org.apache.shiro.spring.boot.ldap;

import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.shared.ldap.model.cursor.EntryCursor;
import org.apache.directory.shared.ldap.model.entry.Attribute;
import org.apache.directory.shared.ldap.model.entry.Entry;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.spring.boot.ShiroLdapProperties;
import org.apache.shiro.spring.boot.ldap.exception.IncorrectLdapException;
import org.apache.shiro.spring.boot.ldap.token.LdapLoginToken;
import org.apache.shiro.spring.boot.ldap.utils.LdapConnectionUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("LdapPrincipalRepository Tests")
class LdapPrincipalRepositoryTest {

    private LdapPrincipalRepository createRepo() throws Exception {
        LdapPrincipalRepository repo = new LdapPrincipalRepository();
        ShiroLdapProperties props = new ShiroLdapProperties();
        props.setLdapHost("localhost");
        props.setLdapPort(389);
        props.setName("cn=admin");
        props.setCredentials("pass");
        java.lang.reflect.Field f = LdapPrincipalRepository.class.getDeclaredField("properties");
        f.setAccessible(true);
        f.set(repo, props);
        return repo;
    }

    @Test
    @DisplayName("Instance can be created via constructor")
    void testInstantiation() {
        LdapPrincipalRepository instance = new LdapPrincipalRepository();
        assertThat(instance).isNotNull();
    }

    @Test
    @DisplayName("Repository extends ShiroPrincipalRepositoryImpl")
    void testInheritance() {
        assertThat(org.apache.shiro.biz.authz.principal.ShiroPrincipalRepositoryImpl.class
                .isAssignableFrom(LdapPrincipalRepository.class)).isTrue();
    }

    @Test
    @DisplayName("getAuthenticationInfo returns info on successful LDAP search")
    void testGetAuthenticationInfoSuccess() throws Exception {
        LdapConnection mockConn = mock(LdapConnection.class);
        EntryCursor mockCursor = mock(EntryCursor.class);
        Entry mockEntry = mock(Entry.class);
        Attribute uidAttr = mock(Attribute.class);

        when(uidAttr.getId()).thenReturn("uid");
        when(uidAttr.getString()).thenReturn("testuser");
        when(mockEntry.getAttributes()).thenReturn(Collections.singletonList(uidAttr));
        when(mockCursor.next()).thenReturn(true, false);
        when(mockCursor.get()).thenReturn(mockEntry);
        when(mockConn.search(anyString(), anyString(), any(), anyString())).thenReturn(mockCursor);

        LdapPrincipalRepository repo = createRepo();

        try (MockedStatic<LdapConnectionUtils> mocked = Mockito.mockStatic(LdapConnectionUtils.class)) {
            mocked.when(() -> LdapConnectionUtils.openConnection(anyString(), anyInt(), anyString(), anyString()))
                    .thenReturn(mockConn);
            mocked.when(() -> LdapConnectionUtils.closeConnection(any())).then(invocation -> null);

            LdapLoginToken token = new LdapLoginToken();
            AuthenticationInfo info = repo.getAuthenticationInfo(token);
            assertThat(info).isNotNull();
        }
    }

    @Test
    @DisplayName("getAuthenticationInfo throws IncorrectLdapException on connection failure")
    void testGetAuthenticationInfoConnectionFailure() throws Exception {
        LdapPrincipalRepository repo = createRepo();

        try (MockedStatic<LdapConnectionUtils> mocked = Mockito.mockStatic(LdapConnectionUtils.class)) {
            mocked.when(() -> LdapConnectionUtils.openConnection(anyString(), anyInt(), anyString(), anyString()))
                    .thenThrow(new IncorrectLdapException("connection failed"));

            LdapLoginToken token = new LdapLoginToken();
            assertThatThrownBy(() -> repo.getAuthenticationInfo(token))
                    .isInstanceOf(IncorrectLdapException.class);
        }
    }

    @Test
    @DisplayName("getAuthenticationInfo handles roles and perms attributes")
    void testGetAuthenticationInfoWithRolesAndPerms() throws Exception {
        LdapConnection mockConn = mock(LdapConnection.class);
        EntryCursor mockCursor = mock(EntryCursor.class);
        Entry mockEntry = mock(Entry.class);

        Attribute uidAttr = mock(Attribute.class);
        when(uidAttr.getId()).thenReturn("uid");
        when(uidAttr.getString()).thenReturn("testuser");

        Attribute rolesAttr = mock(Attribute.class);
        when(rolesAttr.getId()).thenReturn("roles");
        when(rolesAttr.getString()).thenReturn("admin,user");

        Attribute permsAttr = mock(Attribute.class);
        when(permsAttr.getId()).thenReturn("perms");
        when(permsAttr.getString()).thenReturn("read,write");

        Attribute ukeyAttr = mock(Attribute.class);
        when(ukeyAttr.getId()).thenReturn("ukey");
        when(ukeyAttr.getString()).thenReturn("key123");

        Attribute snAttr = mock(Attribute.class);
        when(snAttr.getId()).thenReturn("sn");
        when(snAttr.getString()).thenReturn("Test User");

        Attribute cnAttr = mock(Attribute.class);
        when(cnAttr.getId()).thenReturn("cn");
        when(cnAttr.getString()).thenReturn("Test");

        List<Attribute> attrs = Arrays.asList(uidAttr, rolesAttr, permsAttr, ukeyAttr, snAttr, cnAttr);
        when(mockEntry.getAttributes()).thenReturn(attrs);
        when(mockCursor.next()).thenReturn(true, false);
        when(mockCursor.get()).thenReturn(mockEntry);
        when(mockConn.search(anyString(), anyString(), any(), anyString())).thenReturn(mockCursor);

        LdapPrincipalRepository repo = createRepo();

        try (MockedStatic<LdapConnectionUtils> mocked = Mockito.mockStatic(LdapConnectionUtils.class)) {
            mocked.when(() -> LdapConnectionUtils.openConnection(anyString(), anyInt(), anyString(), anyString()))
                    .thenReturn(mockConn);
            mocked.when(() -> LdapConnectionUtils.closeConnection(any())).then(invocation -> null);

            LdapLoginToken token = new LdapLoginToken();
            AuthenticationInfo info = repo.getAuthenticationInfo(token);
            assertThat(info).isNotNull();
            assertThat(info.getPrincipals().getPrimaryPrincipal())
                    .isInstanceOf(org.apache.shiro.biz.authz.principal.ShiroPrincipal.class);
        }
    }
}

package com.chihab.spring.security.security;

import com.google.common.collect.Sets;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

public enum ApplicationUserRole  {
    STUDENT(Sets.newHashSet()),
    ADMIN(Sets.newHashSet(ApplicaionUserPermission.STUDENT_READ
            ,ApplicaionUserPermission.STUDENT_WRITE
            ,ApplicaionUserPermission.COURSE_READ
            ,ApplicaionUserPermission.COURSE_WRITE)),
    ADMINTRAINEE(Sets.newHashSet(ApplicaionUserPermission.STUDENT_READ
            ,ApplicaionUserPermission.COURSE_READ));

    private final Set<ApplicaionUserPermission> permissions;

    ApplicationUserRole(Set<ApplicaionUserPermission> permissions) {
        this.permissions = permissions;
    }

    public Set<ApplicaionUserPermission> getPermissions() {
        return permissions;
    }

    public Set<SimpleGrantedAuthority> getGrantedAuthorities()
    {
       Set<SimpleGrantedAuthority> permissions= getPermissions().stream()
                .map(permission->new SimpleGrantedAuthority(permission.getPermission()))
                .collect(Collectors.toSet());
       permissions.add(new SimpleGrantedAuthority("ROLE_"+this.name()));
       return permissions;
    }
}

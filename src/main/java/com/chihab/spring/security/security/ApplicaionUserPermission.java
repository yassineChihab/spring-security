package com.chihab.spring.security.security;

public enum ApplicaionUserPermission {
    STUDENT_READ("student:read"),
    STUDENT_WRITE("student:write"),

    COURSE_READ("course:read"),
    COURSE_WRITE("course:write"),
    ;


    private final  String permission;

    ApplicaionUserPermission(String permission) {
        this.permission = permission;
    }

    public String getPermission() {
        return permission;
    }
}

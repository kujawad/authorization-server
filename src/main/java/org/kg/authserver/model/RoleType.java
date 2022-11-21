package org.kg.authserver.model;

public enum RoleType {
    ROLE_USER, ROLE_MODERATOR, ROLE_ADMIN;

    public static class Constants {
        public static final String ROLE_ADMIN = "ROLE_ADMIN";
    }
}

package org.jbei.ice.shared.dto;

import java.util.Date;

import com.google.gwt.user.client.rpc.IsSerializable;

public class AccountInfo implements IsSerializable {

    private long id;
    private String sessionId;
    private String email;
    private String initials;
    private String firstName;
    private String lastName;
    private String institution;
    private String description;
    private Date lastLogin;
    private long userEntryCount;
    private long visibleEntryCount;
    private boolean isAdmin;
    private int newMessageCount;

    public AccountInfo() {
    }

    public String getEmail() {
        return email;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public void setInstitution(String institution) {
        this.institution = institution;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getLastName() {
        return lastName;
    }

    public String getFullName() {
        return this.firstName + " " + this.lastName;
    }

    public String getInstitution() {
        return institution;
    }

    public String getDescription() {
        return description;
    }

    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    public long getUserEntryCount() {
        return userEntryCount;
    }

    public void setUserEntryCount(long ownerEntryCount) {
        this.userEntryCount = ownerEntryCount;
    }

    public long getVisibleEntryCount() {
        return visibleEntryCount;
    }

    public void setVisibleEntryCount(long visibleEntryCount) {
        this.visibleEntryCount = visibleEntryCount;
    }

    public boolean isAdmin() {
        return isAdmin;
    }

    public void setAdmin(boolean isModerator) {
        this.isAdmin = isModerator;
    }

    public String getInitials() {
        return initials;
    }

    public void setInitials(String initials) {
        this.initials = initials;
    }

    public Date getLastLogin() {
        return lastLogin;
    }

    public void setLastLogin(Date date) {
        this.lastLogin = date;
    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public int getNewMessageCount() {
        return newMessageCount;
    }

    public void setNewMessageCount(int newMessageCount) {
        this.newMessageCount = newMessageCount;
    }
}

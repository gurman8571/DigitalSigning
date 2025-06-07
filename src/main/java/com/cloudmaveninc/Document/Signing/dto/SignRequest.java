package com.cloudmaveninc.Document.Signing.dto;

import java.time.LocalDateTime;

public class SignRequest {

    private String base64Content;
    private String documentName;
    private String organisationId;
    private String actionName;
    private String moduleName;
    private String title;
    private boolean isSandbox;
    private LocalDateTime dateTime;

    // Getters and Setters

    public String getBase64Content() {
        return base64Content;
    }

    public void setBase64Content(String base64Content) {
        this.base64Content = base64Content;
    }

    public String getDocumentName() {
        return documentName;
    }

    public void setDocumentName(String documentName) {
        this.documentName = documentName;
    }

    public String getOrganisationId() {
        return organisationId;
    }

    public void setOrganisationId(String organisationId) {
        this.organisationId = organisationId;
    }

    public String getActionName() {
        return actionName;
    }

    public void setActionName(String actionName) {
        this.actionName = actionName;
    }

    public String getModuleName() {
        return moduleName;
    }

    public void setModuleName(String moduleName) {
        this.moduleName = moduleName;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public boolean isSandbox() {
        return isSandbox;
    }

    public void setSandbox(boolean isSandbox) {
        this.isSandbox = isSandbox;
    }

    public LocalDateTime getDateTime() {
        return dateTime;
    }

    public void setDateTime(LocalDateTime dateTime) {
        this.dateTime = dateTime;
    }
}


package org.jenkinsci.plugins.osfbuildersuiteforsfcc.dataimport.model;

import hudson.model.InvisibleAction;

public class DataImportAction extends InvisibleAction {
    private final String sha1Hash;

    public DataImportAction(String sha1Hash) {
        this.sha1Hash = sha1Hash;
    }

    public String getSha1Hash() {
        return sha1Hash;
    }
}

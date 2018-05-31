package org.jenkinsci.plugins.osfbuildersuiteforsfcc.dataimport.model;

import hudson.model.InvisibleAction;

public class DataImportAction extends InvisibleAction {
    private final String dataFingerprint;

    public DataImportAction(String dataFingerprint) {
        this.dataFingerprint = dataFingerprint;
    }

    public String getDataFingerprint() {
        return dataFingerprint;
    }
}

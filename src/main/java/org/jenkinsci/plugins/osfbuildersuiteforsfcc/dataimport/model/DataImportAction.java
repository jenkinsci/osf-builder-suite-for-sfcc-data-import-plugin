package org.jenkinsci.plugins.osfbuildersuiteforsfcc.dataimport.model;

import hudson.model.InvisibleAction;

import java.util.List;

public class DataImportAction extends InvisibleAction {
    private final List<String> dataFingerprints;

    public DataImportAction(List<String> dataFingerprints) {
        this.dataFingerprints = dataFingerprints;
    }

    public List<String> getDataFingerprints() {
        return dataFingerprints;
    }
}

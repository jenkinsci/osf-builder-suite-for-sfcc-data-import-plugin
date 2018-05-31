package org.jenkinsci.plugins.osfbuildersuiteforsfcc.dataimport.model;

import hudson.EnvVars;
import hudson.model.EnvironmentContributingAction;
import hudson.model.Run;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;

public class DataImportEnvAction implements EnvironmentContributingAction {
    private final Integer dataImportNumber;
    private final String dataImportStatus;

    public DataImportEnvAction(Integer dataImportNumber, String dataImportStatus) {
        this.dataImportNumber = dataImportNumber;
        this.dataImportStatus = dataImportStatus;
    }

    public Integer getDataImportNumber() {
        return dataImportNumber;
    }

    public String getDataImportStatus() {
        return dataImportStatus;
    }

    @Override
    public void buildEnvironment(@Nonnull Run<?, ?> run, @Nonnull EnvVars envVars) {
        envVars.put(String.format("OSF_BUILDER_SUITE_DATA_IMPORT_STATUS%s", dataImportNumber), dataImportStatus);
    }

    @CheckForNull
    @Override
    public String getIconFileName() {
        return null;
    }

    @CheckForNull
    @Override
    public String getDisplayName() {
        return null;
    }

    @CheckForNull
    @Override
    public String getUrlName() {
        return null;
    }
}

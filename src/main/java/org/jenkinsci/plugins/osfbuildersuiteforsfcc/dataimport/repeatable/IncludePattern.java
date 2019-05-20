package org.jenkinsci.plugins.osfbuildersuiteforsfcc.dataimport.repeatable;

import hudson.Extension;
import hudson.model.Describable;
import hudson.model.Descriptor;
import jenkins.model.Jenkins;
import org.kohsuke.stapler.DataBoundConstructor;

import java.io.Serializable;

public class IncludePattern implements Serializable, Describable<IncludePattern> {

    private final String includePattern;

    @DataBoundConstructor
    public IncludePattern(String includePattern) {
        this.includePattern = includePattern;
    }

    public String getIncludePattern() {
        return includePattern;
    }

    @Override
    public DescriptorImpl getDescriptor() {
        return (DescriptorImpl) Jenkins.get().getDescriptor(getClass());
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<IncludePattern> {

        @Override
        public String getDisplayName() {
            return "OSF Builder Suite For Salesforce Commerce Cloud :: Data Import (IncludePattern)";
        }
    }
}

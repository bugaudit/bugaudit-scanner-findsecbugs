package me.shib.bugaudit.scanner.java.findsecbugs;

import me.shib.bugaudit.commons.BugAuditException;
import me.shib.bugaudit.scanner.BugAuditScanResult;
import me.shib.bugaudit.scanner.BugAuditScanner;
import me.shib.bugaudit.scanner.Lang;

public final class FindSecBugsScanner extends BugAuditScanner {

    private static transient final Lang lang = Lang.Java;
    private static transient final String tool = "FindSecBugs";

    private BugAuditScanResult result;

    public FindSecBugsScanner() throws BugAuditException {
        super();
        this.getBugAuditScanResult().addKey("SAST-Warning");
        this.result = getBugAuditScanResult();
    }

    @Override
    protected Lang getLang() {
        return lang;
    }

    @Override
    public String getTool() {
        return tool;
    }

    @Override
    protected void scan() throws Exception {
        //TODO Scanning Logic Goes Here
    }
}

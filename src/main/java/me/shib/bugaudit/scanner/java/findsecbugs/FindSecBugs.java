package me.shib.bugaudit.scanner.java.findsecbugs;

public class FindSecBugs {

    public String moduleName;
    public String bugType;
    public String instanceHash;
    public String message;
    public String className;
    public String filePath;
    public String lineNumber;
    public Integer severity;
    public String priority;

    public String getModuleName() {
        return moduleName;
    }

    public String getBugType() {
        return bugType;
    }

    public String getInstanceHash() {
        return instanceHash;
    }

    public String getMessage() {
        return message;
    }

    public String getClassName() {
        return className;
    }

    public String getFilePath() {
        return filePath;
    }

    public String getLineNumber() {
        return lineNumber;
    }

    public Integer getSeverity() {
        return severity;
    }

    public String getPriority() {
        return priority;
    }
}

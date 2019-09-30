package me.shib.bugaudit.scanner.java.findsecbugs;

public class FindSecBugsWarning {

    private String moduleName;
    private String bugType;
    private String instanceHash;
    private String message;
    private String className;
    private String filePath;
    private String lineNumber;
    private Integer severity;
    private String priority;

    public void setModuleName(String moduleName) {
        this.moduleName = moduleName;
    }

    public void setBugType(String bugType) {
        this.bugType = bugType;
    }

    public void setInstanceHash(String instanceHash) {
        this.instanceHash = instanceHash;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public void setClassName(String className) {
        this.className = className;
    }

    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }

    public void setLineNumber(String lineNumber) {
        this.lineNumber = lineNumber;
    }

    public void setSeverity(Integer severity) {
        this.severity = severity;
    }

    public void setPriority(String priority) {
        this.priority = priority;
    }

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
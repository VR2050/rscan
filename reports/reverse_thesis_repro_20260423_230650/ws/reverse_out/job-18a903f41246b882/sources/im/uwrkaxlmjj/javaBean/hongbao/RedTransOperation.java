package im.uwrkaxlmjj.javaBean.hongbao;

/* JADX INFO: loaded from: classes2.dex */
public class RedTransOperation {
    private String businessKey;
    private String groups;
    private String nonceStr;
    private String serialCode;
    private String userId;
    private String version;

    public RedTransOperation(String serialCode, String userId, String nonceStr, String businessKey, String version) {
        this.serialCode = serialCode;
        this.userId = userId;
        this.nonceStr = nonceStr;
        this.businessKey = businessKey;
        this.version = version;
    }

    public RedTransOperation(String serialCode, String userId, String groups, String nonceStr, String businessKey, String version) {
        this.serialCode = serialCode;
        this.userId = userId;
        this.groups = groups;
        this.nonceStr = nonceStr;
        this.businessKey = businessKey;
        this.version = version;
    }

    public String getGroups() {
        return this.groups;
    }

    public void setGroups(String groups) {
        this.groups = groups;
    }

    public String getSerialCode() {
        return this.serialCode;
    }

    public void setSerialCode(String serialCode) {
        this.serialCode = serialCode;
    }

    public String getUserId() {
        return this.userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getNonceStr() {
        return this.nonceStr;
    }

    public void setNonceStr(String nonceStr) {
        this.nonceStr = nonceStr;
    }

    public String getBusinessKey() {
        return this.businessKey;
    }

    public void setBusinessKey(String businessKey) {
        this.businessKey = businessKey;
    }

    public String getVersion() {
        return this.version;
    }

    public void setVersion(String version) {
        this.version = version;
    }
}

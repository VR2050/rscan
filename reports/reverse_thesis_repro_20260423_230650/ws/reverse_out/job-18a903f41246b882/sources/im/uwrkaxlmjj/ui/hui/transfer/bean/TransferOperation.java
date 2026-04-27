package im.uwrkaxlmjj.ui.hui.transfer.bean;

/* JADX INFO: loaded from: classes5.dex */
public class TransferOperation {
    private String businessKey;
    private String nonceStr;
    private String serialCode;
    private String userId;
    private String version;

    public TransferOperation(String serialCode, String userId, String nonceStr, String businessKey, String version) {
        this.serialCode = serialCode;
        this.userId = userId;
        this.nonceStr = nonceStr;
        this.businessKey = businessKey;
        this.version = version;
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

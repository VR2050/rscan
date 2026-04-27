package im.uwrkaxlmjj.ui.wallet.model;

/* JADX INFO: loaded from: classes5.dex */
public class PayPasswordReqBean {
    private String businessKey;
    private String code;
    private String confirmPayPassWord;
    private String payPassWord;
    private String safetyCode;
    private int type;
    private int userId;

    public String getBusinessKey() {
        return this.businessKey;
    }

    public void setBusinessKey(String businessKey) {
        this.businessKey = businessKey;
    }

    public int getUserId() {
        return this.userId;
    }

    public void setUserId(int userId) {
        this.userId = userId;
    }

    public String getPayPassWord() {
        return this.payPassWord;
    }

    public void setPayPassWord(String payPassWord) {
        this.payPassWord = payPassWord;
    }

    public String getConfirmPayPassWord() {
        return this.confirmPayPassWord;
    }

    public void setConfirmPayPassWord(String confirmPayPassWord) {
        this.confirmPayPassWord = confirmPayPassWord;
    }

    public int getType() {
        return this.type;
    }

    public void setType(int type) {
        this.type = type;
    }

    public String getSafetyCode() {
        return this.safetyCode;
    }

    public void setSafetyCode(String safetyCode) {
        this.safetyCode = safetyCode;
    }

    public String getCode() {
        return this.code;
    }

    public void setCode(String code) {
        this.code = code;
    }
}

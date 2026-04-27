package im.uwrkaxlmjj.ui.wallet.model;

/* JADX INFO: loaded from: classes5.dex */
public class BankCardBindReqBean {
    private String bank;
    private String bankCode;
    private String bankName;
    private int bankType;
    private int bindType;
    private String businessKey;
    private String code;
    private String idCard;
    private String openBank;
    private int type;
    private int userId;
    private String userName;

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

    public int getBindType() {
        return this.bindType;
    }

    public void setBindType(int bindType) {
        this.bindType = bindType;
    }

    public int getType() {
        return this.type;
    }

    public void setType(int type) {
        this.type = type;
    }

    public String getBank() {
        return this.bank;
    }

    public void setBank(String bank) {
        this.bank = bank;
    }

    public String getIdCard() {
        return this.idCard;
    }

    public void setIdCard(String idCard) {
        this.idCard = idCard;
    }

    public String getUserName() {
        return this.userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getCode() {
        return this.code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public int getBankType() {
        return this.bankType;
    }

    public void setBankType(int bankType) {
        this.bankType = bankType;
    }

    public String getBankName() {
        return this.bankName;
    }

    public void setBankName(String bankName) {
        this.bankName = bankName;
    }

    public String getBankCode() {
        return this.bankCode;
    }

    public void setBankCode(String bankCode) {
        this.bankCode = bankCode;
    }

    public String getOpenBank() {
        return this.openBank;
    }

    public void setOpenBank(String openBank) {
        this.openBank = openBank;
    }
}

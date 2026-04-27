package im.uwrkaxlmjj.ui.wallet.model;

/* JADX INFO: loaded from: classes5.dex */
public class WithdrawResBean {
    private long cashAmount;
    private String createTime;
    private long freezeOthers;
    private long frozenCash;
    private long id;
    private long otherAmount;
    private long type;
    private int userId;

    public long getId() {
        return this.id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public long getCashAmount() {
        return this.cashAmount;
    }

    public void setCashAmount(long cashAmount) {
        this.cashAmount = cashAmount;
    }

    public long getOtherAmount() {
        return this.otherAmount;
    }

    public void setOtherAmount(long otherAmount) {
        this.otherAmount = otherAmount;
    }

    public long getFrozenCash() {
        return this.frozenCash;
    }

    public void setFrozenCash(long frozenCash) {
        this.frozenCash = frozenCash;
    }

    public long getFreezeOthers() {
        return this.freezeOthers;
    }

    public void setFreezeOthers(long freezeOthers) {
        this.freezeOthers = freezeOthers;
    }

    public int getUserId() {
        return this.userId;
    }

    public void setUserId(int userId) {
        this.userId = userId;
    }

    public long getType() {
        return this.type;
    }

    public void setType(long type) {
        this.type = type;
    }

    public String getCreateTime() {
        return this.createTime;
    }

    public void setCreateTime(String createTime) {
        this.createTime = createTime;
    }
}

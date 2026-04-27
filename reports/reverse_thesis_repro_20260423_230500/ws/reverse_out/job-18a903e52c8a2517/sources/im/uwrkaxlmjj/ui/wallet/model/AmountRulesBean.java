package im.uwrkaxlmjj.ui.wallet.model;

import java.io.Serializable;

/* JADX INFO: loaded from: classes5.dex */
public class AmountRulesBean implements Serializable {
    private String amount;
    private String channelCode;
    private String id;
    private String maxAmount;
    private String minAmount;
    private String payType;
    private int self;

    public String getMinAmount() {
        return this.minAmount;
    }

    public void setMinAmount(String minAmount) {
        this.minAmount = minAmount;
    }

    public String getAmount() {
        return this.amount;
    }

    public void setAmount(String amount) {
        this.amount = amount;
    }

    public String getPayType() {
        return this.payType;
    }

    public void setPayType(String payType) {
        this.payType = payType;
    }

    public int getSelf() {
        return this.self;
    }

    public void setSelf(int self) {
        this.self = self;
    }

    public String getId() {
        return this.id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getMaxAmount() {
        return this.maxAmount;
    }

    public void setMaxAmount(String maxAmount) {
        this.maxAmount = maxAmount;
    }

    public String getChannelCode() {
        return this.channelCode;
    }

    public void setChannelCode(String channelCode) {
        this.channelCode = channelCode;
    }
}

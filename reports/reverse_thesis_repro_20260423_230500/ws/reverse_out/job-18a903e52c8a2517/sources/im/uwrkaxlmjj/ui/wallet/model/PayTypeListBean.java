package im.uwrkaxlmjj.ui.wallet.model;

import java.io.Serializable;

/* JADX INFO: loaded from: classes5.dex */
public class PayTypeListBean implements Serializable {
    private AmountRulesBean amountRules;
    private String belongType;
    private String name;
    private String payType;
    private String rate;
    private int supportId;
    private int templateId;

    public String getBelongType() {
        return this.belongType;
    }

    public void setBelongType(String belongType) {
        this.belongType = belongType;
    }

    public String getPayType() {
        return this.payType;
    }

    public void setPayType(String payType) {
        this.payType = payType;
    }

    public AmountRulesBean getAmountRules() {
        return this.amountRules;
    }

    public void setAmountRules(AmountRulesBean amountRules) {
        this.amountRules = amountRules;
    }

    public String getRate() {
        return this.rate;
    }

    public void setRate(String rate) {
        this.rate = rate;
    }

    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getSupportId() {
        return this.supportId;
    }

    public void setSupportId(int supportId) {
        this.supportId = supportId;
    }

    public int getTemplateId() {
        return this.templateId;
    }

    public void setTemplateId(int templateId) {
        this.templateId = templateId;
    }
}

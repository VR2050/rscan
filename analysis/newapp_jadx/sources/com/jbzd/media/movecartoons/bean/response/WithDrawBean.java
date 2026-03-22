package com.jbzd.media.movecartoons.bean.response;

import java.util.List;

/* loaded from: classes2.dex */
public class WithDrawBean {
    public String active_tips;
    private String balance;
    private String fee_rate;
    public String link;
    private String min_num;
    private List<String> payments;
    private String rate;
    private String tips;

    public String getBalance() {
        return this.balance;
    }

    public String getFee_rate() {
        return this.fee_rate;
    }

    public String getMin_num() {
        return this.min_num;
    }

    public List<String> getPayments() {
        return this.payments;
    }

    public String getRate() {
        return this.rate;
    }

    public String getTips() {
        return this.tips;
    }

    public void setBalance(String str) {
        this.balance = str;
    }

    public void setFee_rate(String str) {
        this.fee_rate = str;
    }

    public void setMin_num(String str) {
        this.min_num = str;
    }

    public void setPayments(List<String> list) {
        this.payments = list;
    }

    public void setRate(String str) {
        this.rate = str;
    }

    public void setTips(String str) {
        this.tips = str;
    }
}

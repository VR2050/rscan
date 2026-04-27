package im.uwrkaxlmjj.ui.wallet.model;

import java.io.Serializable;

/* JADX INFO: loaded from: classes5.dex */
public class PayChannelBean implements Serializable {
    private String channelCode;
    private PayTypeListBean payType;

    public String getChannelCode() {
        return this.channelCode;
    }

    public void setChannelCode(String channelCode) {
        this.channelCode = channelCode;
    }

    public PayTypeListBean getPayType() {
        return this.payType;
    }

    public void setPayType(PayTypeListBean payType) {
        this.payType = payType;
    }
}

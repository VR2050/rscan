package im.uwrkaxlmjj.ui.wallet.model;

import java.util.ArrayList;

/* JADX INFO: loaded from: classes5.dex */
public class PayChannelsResBean {
    private String channelCode;
    private ArrayList<PayTypeListBean> payTypeList;

    public String getChannelCode() {
        return this.channelCode;
    }

    public void setChannelCode(String channelCode) {
        this.channelCode = channelCode;
    }

    public ArrayList<PayTypeListBean> getPayTypeList() {
        return this.payTypeList;
    }

    public void setPayTypeList(ArrayList<PayTypeListBean> payTypeList) {
        this.payTypeList = payTypeList;
    }
}

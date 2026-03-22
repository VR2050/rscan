package com.jbzd.media.movecartoons.bean.response;

import android.text.TextUtils;

/* loaded from: classes2.dex */
public class OrderBean {
    public String created_at;
    public String days;
    public String group_name;

    /* renamed from: id */
    public String f9971id;
    public String order_sn;
    public String pay_at;
    public String pay_name;
    public String price;
    public String real_price;
    public String status;
    public String status_text;

    public boolean getIsFail() {
        return TextUtils.equals(ChatMsgBean.SERVICE_ID, this.status);
    }

    public boolean getIsSuccess() {
        return TextUtils.equals("1", this.status);
    }
}

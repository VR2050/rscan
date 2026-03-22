package com.jbzd.media.movecartoons.bean.response;

import android.text.TextUtils;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes2.dex */
public class WorksBean extends VideoItemBean {
    public String date;
    public String reason;
    public String status;

    public String getStatusTxt() {
        String str = this.status;
        if (str == null) {
            return "审核中";
        }
        str.hashCode();
        str.hashCode();
        switch (str) {
            case "-2":
                StringBuilder m586H = C1499a.m586H("未通过 ");
                m586H.append(this.reason);
                break;
        }
        return "审核中";
    }

    public boolean isNotPass() {
        return TextUtils.equals(this.status, "-2");
    }
}

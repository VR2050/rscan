package im.uwrkaxlmjj.javaBean.cdnVip;

import com.blankj.utilcode.util.TimeUtils;

/* JADX INFO: loaded from: classes2.dex */
public class CdnVipInfoBean {
    private boolean AutoPay;
    private int BgnTime;
    private int EndTime;
    public int level;
    private int state;

    public boolean isAutoPay() {
        return this.AutoPay;
    }

    public boolean cdnVipIsAvailable() {
        return this.state == 2;
    }

    public String getEndTimeFormat() {
        return TimeUtils.millis2String(((long) this.EndTime) * 1000, "yyyy.MM.dd");
    }
}

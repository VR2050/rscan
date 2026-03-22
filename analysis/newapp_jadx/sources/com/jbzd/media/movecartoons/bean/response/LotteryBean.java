package com.jbzd.media.movecartoons.bean.response;

import android.text.TextUtils;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public class LotteryBean {
    public String can_lottery;

    /* renamed from: id */
    public String f9967id;
    public String is_log;
    public String name;
    public String point;
    public String type;
    public String vip_num;

    public boolean canLottery() {
        String str = this.can_lottery;
        return !(str == null || str.length() == 0) && Intrinsics.areEqual(str, "y");
    }

    public boolean isLog() {
        return TextUtils.equals("1", this.is_log);
    }

    public boolean isLotteryVip() {
        return TextUtils.equals(VideoTypeBean.video_type_vip, this.type);
    }
}

package com.jbzd.media.movecartoons.bean.response;

import android.text.TextUtils;
import java.io.Serializable;

/* loaded from: classes2.dex */
public class CreatorBean implements Serializable {
    public String avatar;
    public String creator_id;
    public String fans;
    public boolean isAll = false;
    public String is_buy;
    public String is_follow;
    public String nickname;
    public String resource_num;
    public String user_id;

    public Boolean hadBuy() {
        return Boolean.valueOf(TextUtils.equals("y", this.is_buy));
    }

    public Boolean hadFollow() {
        return Boolean.valueOf(TextUtils.equals("y", this.is_follow));
    }
}

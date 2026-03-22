package com.jbzd.media.movecartoons.bean.response;

import android.text.TextUtils;
import java.io.Serializable;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public class ActorBean implements Serializable {
    public String avatar;
    public String desc;
    public String fans;
    public String is_follow;
    public String nickname;
    public String resource_num;
    public String type;
    public String user_id;

    public String getTypeName() {
        return TextUtils.equals(this.type, "1") ? "专业工作室" : TextUtils.equals(this.type, "2") ? "原创大神" : TextUtils.equals(this.type, "3") ? "资深撸友" : "";
    }

    public boolean hasFollow() {
        String str = this.is_follow;
        return !(str == null || str.length() == 0) && Intrinsics.areEqual(str, "y");
    }
}

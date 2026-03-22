package com.jbzd.media.movecartoons.bean.response;

import android.text.TextUtils;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public class VideoGroupDetailBean {
    public String collect_num;
    public String group_type;

    /* renamed from: id */
    public String f9998id;
    public String img;
    public String is_love;
    public String name;
    public String work_num;

    public boolean getHasFollow() {
        String str = this.is_love;
        return !(str == null || str.length() == 0) && Intrinsics.areEqual(str, "y");
    }

    public boolean isLong() {
        return TextUtils.equals("long", this.group_type);
    }
}

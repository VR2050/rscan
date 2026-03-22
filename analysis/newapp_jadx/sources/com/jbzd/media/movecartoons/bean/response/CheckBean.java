package com.jbzd.media.movecartoons.bean.response;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public class CheckBean {
    public String is_follow;
    public String is_love;

    public boolean hasFollow() {
        String str = this.is_follow;
        return !(str == null || str.length() == 0) && Intrinsics.areEqual(str, "y");
    }

    public boolean hasLove() {
        String str = this.is_love;
        return !(str == null || str.length() == 0) && Intrinsics.areEqual(str, "y");
    }
}

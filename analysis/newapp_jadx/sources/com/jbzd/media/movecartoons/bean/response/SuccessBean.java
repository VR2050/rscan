package com.jbzd.media.movecartoons.bean.response;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public class SuccessBean {
    public String status;

    public boolean isStatusY() {
        String str = this.status;
        return !(str == null || str.length() == 0) && Intrinsics.areEqual(str, "y");
    }
}

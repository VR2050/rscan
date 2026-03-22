package com.jbzd.media.movecartoons.bean;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public class TokenBean {
    public String expired_at;

    /* renamed from: ip */
    public String f9924ip;
    public String set_pwd;
    public String token;
    public String user_id;
    public String username;

    public boolean isNeedSetPwd() {
        String str = this.set_pwd;
        return !(str == null || str.length() == 0) && Intrinsics.areEqual(str, "y");
    }
}

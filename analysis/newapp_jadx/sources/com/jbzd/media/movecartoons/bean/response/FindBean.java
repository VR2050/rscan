package com.jbzd.media.movecartoons.bean.response;

import android.text.TextUtils;

/* loaded from: classes2.dex */
public class FindBean {
    public static final String status_register = "register";
    public static final String status_success = "success";
    public String status;

    public boolean isNeedRegister() {
        return TextUtils.equals(this.status, status_register);
    }
}

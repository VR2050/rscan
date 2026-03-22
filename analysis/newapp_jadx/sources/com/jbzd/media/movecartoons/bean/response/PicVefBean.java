package com.jbzd.media.movecartoons.bean.response;

import android.text.TextUtils;

/* loaded from: classes2.dex */
public class PicVefBean {
    public String key;
    public String value;

    public String getBase64WithoutHead() {
        if (!(!TextUtils.isEmpty(this.value))) {
            return "";
        }
        return this.value.substring(this.value.indexOf(44) + 1);
    }
}

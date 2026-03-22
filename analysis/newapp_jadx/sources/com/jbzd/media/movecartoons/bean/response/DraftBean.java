package com.jbzd.media.movecartoons.bean.response;

import android.text.TextUtils;
import java.io.Serializable;
import java.util.List;

/* loaded from: classes2.dex */
public class DraftBean implements Serializable {
    public String content;
    public String error_msg;

    /* renamed from: id */
    public String f9948id;
    public List<String> images;
    public String status;
    public String time_label;
    public String title;
    public String update_at;

    public boolean getIsShowError() {
        return (TextUtils.equals(this.status, "0") || TextUtils.equals(this.status, "1")) ? false : true;
    }
}

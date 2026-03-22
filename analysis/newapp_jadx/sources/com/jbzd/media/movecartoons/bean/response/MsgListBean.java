package com.jbzd.media.movecartoons.bean.response;

import android.text.TextUtils;

/* loaded from: classes2.dex */
public class MsgListBean {
    public String classify;
    public String content;
    public String headico;

    /* renamed from: id */
    public String f9970id;
    public String is_my;
    public String is_read;
    public String link;
    public String nickname;
    public String time_label;
    public String title;
    public String type;
    public String updated_at;
    public String user_id;

    public static boolean isNotice(String str) {
        return TextUtils.equals(str, "-2");
    }

    public boolean isService() {
        return TextUtils.equals(this.user_id, ChatMsgBean.SERVICE_ID);
    }

    public boolean isNotice() {
        return TextUtils.equals(this.user_id, "-2");
    }
}

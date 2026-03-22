package com.jbzd.media.movecartoons.bean.response;

import android.text.TextUtils;
import java.util.List;

/* loaded from: classes2.dex */
public class CommentBean {
    public String child_nickname;
    public String child_user_id;
    public String content;

    /* renamed from: id */
    public String f9941id;
    public String img;
    public String link;
    public String love;
    public String love_status;
    public String nickname;
    public String object_content;
    public String object_id;
    public String object_img;
    public String object_title;
    public String parent_id;
    public String reward;
    public String rights_ico;
    public List<CommentBean> sub_items;
    public String time_label;
    public String type;
    public String user_id;

    public boolean getHasLove() {
        return TextUtils.equals("y", this.love_status);
    }
}

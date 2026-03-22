package com.jbzd.media.movecartoons.bean.response;

import android.text.TextUtils;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import p005b.p067b.p068a.p069a.p070a.p074j.InterfaceC1296a;

/* loaded from: classes2.dex */
public class HomeVideoGroupBean implements InterfaceC1296a {
    public String anchor_name;
    public String collect_num;
    public String creator_name;
    public String group_type;

    /* renamed from: id */
    public String f9960id;
    public String img;
    public String is_free;
    public String is_love;
    public List<VideoItemBean> items;
    public String name;
    public List<String> options;
    public String play_num;
    public String user_id;
    public String work_num;

    public boolean getHasFollow() {
        String str = this.is_love;
        return !(str == null || str.length() == 0) && Intrinsics.areEqual(str, "y");
    }

    @Override // p005b.p067b.p068a.p069a.p070a.p074j.InterfaceC1296a
    public int getItemType() {
        String str = this.group_type;
        str.hashCode();
        if (str.equals("long")) {
            return 2;
        }
        return !str.equals("short") ? -1 : 3;
    }

    public Boolean isLongGroup() {
        return Boolean.valueOf(TextUtils.equals("5", this.group_type));
    }
}

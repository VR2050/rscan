package com.jbzd.media.movecartoons.bean.response.tag;

import android.text.TextUtils;
import androidx.annotation.NonNull;
import java.io.Serializable;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public class TagBean implements Serializable, Cloneable {
    public String desc;
    public String fans;
    public String first_letter;

    /* renamed from: id */
    public String f10032id;
    public String img;
    public String is_love;
    public String key;
    public String name;
    public String order_by;
    public String play_num;
    public String resource_num;
    public String value;
    public Integer watch_limit = 0;
    public String work_num;

    @NonNull
    public Object clone() {
        return super.clone();
    }

    public boolean getHasFollow() {
        String str = this.is_love;
        return !(str == null || str.length() == 0) && Intrinsics.areEqual(str, "y");
    }

    public boolean isFollowFrag() {
        return TextUtils.equals("-2", this.value);
    }
}

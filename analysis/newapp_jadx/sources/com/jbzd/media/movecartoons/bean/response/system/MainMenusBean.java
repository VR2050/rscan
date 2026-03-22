package com.jbzd.media.movecartoons.bean.response.system;

import android.text.TextUtils;
import com.jbzd.media.movecartoons.bean.response.tag.TagBean;
import java.io.Serializable;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public class MainMenusBean implements Serializable, Cloneable {
    public static final String TYPE_APPS_CENTER = "7";
    public static final String TYPE_DAY_PICKS = "8";
    public static final String TYPE_PICK_COLLECTION = "9";
    public static final String TYPE_WEB = "12";
    public String category_id;
    public String code;
    public String filter;

    /* renamed from: id */
    public String f10030id = "";
    public boolean isAll = false;
    public String is_ai;
    public String is_default;
    public String link;
    public String name;
    public String position;
    public ArrayList<TagBean> tabs;
    public String type;

    public Object clone() {
        return super.clone();
    }

    public boolean isAppsCenter() {
        return TextUtils.equals(TYPE_APPS_CENTER, this.type);
    }

    public boolean isDayPicks() {
        return TextUtils.equals(TYPE_DAY_PICKS, this.type);
    }

    public boolean isDefaultTab() {
        String str = this.is_default;
        return !(str == null || str.length() == 0) && Intrinsics.areEqual(str, "y");
    }

    public boolean isPersonalCustomize() {
        return TextUtils.equals("2", this.type);
    }

    public boolean isPickCollection() {
        return TextUtils.equals(TYPE_PICK_COLLECTION, this.type);
    }

    public boolean isWEB() {
        return TextUtils.equals(TYPE_WEB, this.type);
    }

    public static boolean isAppsCenter(String str) {
        return TextUtils.equals(TYPE_APPS_CENTER, str);
    }

    public static boolean isDayPicks(String str) {
        return TextUtils.equals(TYPE_DAY_PICKS, str);
    }

    public static boolean isPickCollection(String str) {
        return TextUtils.equals(TYPE_PICK_COLLECTION, str);
    }
}

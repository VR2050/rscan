package com.jbzd.media.movecartoons.bean.response;

import android.text.TextUtils;
import java.util.List;

/* loaded from: classes2.dex */
public class HomeModuleBean {
    public static final String STYLE_BIG = "3";
    public static final String STYLE_CHANGE = "2";
    public static final String STYLE_HOR = "1";
    public static final String TYPE_LONG_VIDEO = "2";
    public static final String TYPE_SHORT_VIDEO = "3";
    public String desc;

    /* renamed from: id */
    public String f9959id;
    public List<VideoItemBean> items;
    public String link;
    public String name;
    public String number;
    public String order_by;
    public String show_change_btn;
    public int show_type;
    public String style;
    public String tips;
    public String type;

    public int getBlockStyle() {
        if (this.show_type == 2) {
            if (TextUtils.equals("1", this.style)) {
                return 10;
            }
            return TextUtils.equals("2", this.style) ? 9 : 7;
        }
        if (TextUtils.equals("1", this.style)) {
            return 8;
        }
        return TextUtils.equals("2", this.style) ? 6 : 7;
    }

    public boolean isLong() {
        return TextUtils.equals("2", this.type);
    }
}

package com.jbzd.media.movecartoons.bean.response.home;

import com.jbzd.media.movecartoons.bean.response.AppItemNew;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public class AdBean implements Serializable {
    public String auto_jump;
    public String channel_code;
    public String content;
    public AdNewBean data;
    public String height;

    /* renamed from: id */
    public String f10014id;
    public String is_ad;
    public List<AppItemNew> items;
    public String key;
    public String link;
    public String name;
    public String position_code;
    public String time;
    public String title;
    public String type;
    public String width;

    public class AdNewBean implements Serializable {
        public String content = "";

        /* renamed from: id */
        public String f10015id;
        public String is_ad;
        public ArrayList<AppItemNew> items;
        public String link;
        public String name;
        public String position_code;
        public String type;

        public AdNewBean() {
        }
    }
}

package com.jbzd.media.movecartoons.bean.response;

import com.jbzd.media.movecartoons.bean.response.comicsinfo.Tags;
import com.jbzd.media.movecartoons.bean.response.home.AdBean;
import java.io.Serializable;
import java.util.ArrayList;
import p005b.p067b.p068a.p069a.p070a.p074j.InterfaceC1296a;

/* loaded from: classes2.dex */
public class HomeComicsBlockBean implements InterfaceC1296a {
    public static final int type_comicsstyle_coum2 = 3;
    public static final int type_comicsstyle_coum3 = 2;
    public static final int type_comicsstyle_hor_scroll = 1;
    public static final int type_comicsstyle_unknow = 4;

    /* renamed from: ad */
    public AdBean f9956ad;
    public String filter;
    public String ico;

    /* renamed from: id */
    public String f9957id;
    public ArrayList<ComicsItemBean> items;
    public String name;
    public String page;
    public String page_size;
    public int realPage = 1;
    public int style;

    public class ComicsItemBean implements Serializable, Cloneable {
        public String alias_name;
        public String category;
        public String chapter_count;
        public String click;
        public String comment;
        public String description;
        public String favorite;
        public String ico;

        /* renamed from: id */
        public String f9958id;
        public String img;
        public String is_adult;
        public String money;
        public String name;
        public String pay_type;
        public int realPage = 1;
        public String status;
        public String status_text;
        public String sub_title;
        public ArrayList<Tags> tags;
        public String type;
        public String update_date;
        public String update_status;

        public ComicsItemBean() {
        }
    }

    @Override // p005b.p067b.p068a.p069a.p070a.p074j.InterfaceC1296a
    public int getItemType() {
        int i2 = this.style;
        if (i2 == 1 || i2 == 2 || i2 == 3) {
            return i2;
        }
        return 4;
    }
}

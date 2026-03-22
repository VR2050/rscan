package com.jbzd.media.movecartoons.bean.response.home;

import com.jbzd.media.movecartoons.bean.response.HomeBlockBean;
import com.jbzd.media.movecartoons.bean.response.VideoItemBean;
import java.util.ArrayList;
import p005b.p067b.p068a.p069a.p070a.p074j.InterfaceC1296a;

/* loaded from: classes2.dex */
public class HomeTabBean implements InterfaceC1296a {
    public static final int type_landscape_2_columns = 2;
    public static final int type_landscape_single = 3;
    public static final int type_landscape_single_2_columns = 1;
    public static final int type_landscape_slide = 5;
    public static final int type_portrait_2_columns = 4;
    public static final int type_portrait_seven = 7;
    public static final int type_portrait_slide = 6;

    /* renamed from: ad */
    public AdBean f10016ad;
    public ArrayList<AdBean> banner;
    public ArrayList<HomeBlockBean> block;
    public String filter;

    /* renamed from: id */
    public String f10017id;
    public ArrayList<VideoItemBean> items;
    public String more_canvas;
    public String name;
    public int number;
    public String page_size;
    public String show_change_btn;
    public int show_type;
    public int style;
    public int type;
    public String ico = "";
    public Integer watch_limit = 0;
    public int nextPage = 2;

    @Override // p005b.p067b.p068a.p069a.p070a.p074j.InterfaceC1296a
    public int getItemType() {
        return this.style;
    }

    public String whatType() {
        int i2 = this.type;
        return i2 != 1 ? i2 != 2 ? i2 != 3 ? "不明" : "91暗网" : "深网" : "浅网";
    }
}

package com.jbzd.media.movecartoons.bean.response.novel;

import com.jbzd.media.movecartoons.bean.response.home.AdBean;
import java.util.ArrayList;
import java.util.List;
import p005b.p067b.p068a.p069a.p070a.p074j.InterfaceC1296a;

/* loaded from: classes2.dex */
public class HomeTabNovelBean implements InterfaceC1296a {
    public static final int typemodule_comicsstyle_coum2 = 3;
    public static final int typemodule_comicsstyle_coum3 = 2;
    public static final int typemodule_comicsstyle_horscroll = 1;
    public static final int typemodule_comicsstyle_unknow = 4;

    /* renamed from: ad */
    public AdBean f10024ad;
    public ArrayList<AdBean> banner;
    public List<HomeNovelBlockBean> block;
    public String filter;
    public String ico = "";

    /* renamed from: id */
    public String f10025id;
    public ArrayList<NovelItemsBean> items;
    public String name;
    public String page_size;
    public int style;
    public int type;

    @Override // p005b.p067b.p068a.p069a.p070a.p074j.InterfaceC1296a
    public int getItemType() {
        return this.style;
    }
}

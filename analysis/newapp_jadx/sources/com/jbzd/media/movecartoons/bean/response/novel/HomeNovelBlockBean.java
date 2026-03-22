package com.jbzd.media.movecartoons.bean.response.novel;

import java.util.ArrayList;
import p005b.p067b.p068a.p069a.p070a.p074j.InterfaceC1296a;

/* loaded from: classes2.dex */
public class HomeNovelBlockBean implements InterfaceC1296a {
    public String filter;
    public String ico;

    /* renamed from: id */
    public String f10023id;
    public ArrayList<NovelItemsBean> items;
    public String name;
    public String page;
    public String page_size;
    public String style;

    @Override // p005b.p067b.p068a.p069a.p070a.p074j.InterfaceC1296a
    public int getItemType() {
        return Integer.parseInt(this.style);
    }
}

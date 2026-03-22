package com.jbzd.media.movecartoons.bean.response.home;

import com.jbzd.media.movecartoons.bean.response.HomeComicsBlockBean;
import java.io.Serializable;
import java.util.ArrayList;
import p005b.p067b.p068a.p069a.p070a.p074j.InterfaceC1296a;

/* loaded from: classes2.dex */
public class HomeTabComicsBean implements InterfaceC1296a {
    public static final int typemodule_comicsstyle_coum2 = 3;
    public static final int typemodule_comicsstyle_coum3 = 2;
    public static final int typemodule_comicsstyle_horscroll = 1;
    public static final int typemodule_comicsstyle_unknow = 4;

    /* renamed from: ad */
    public AdBean f10018ad;
    public ArrayList<AdBean> banner;
    public ArrayList<HomeComicsBlockBean> block;
    public ArrayList<Buttons> buttons;
    public String filter;
    public String ico = "";

    /* renamed from: id */
    public String f10019id;
    public ArrayList<HomeComicsBlockBean.ComicsItemBean> items;
    public String name;
    public String page_size;
    public int style;
    public int type;

    public class Buttons implements Serializable {
        public String filter;
        public String ico;
        public String name;
        public String show_type;

        public Buttons() {
        }

        public String getFilter() {
            return this.filter;
        }

        public String getIco() {
            return this.ico;
        }

        public String getName() {
            return this.name;
        }

        public String getShow_type() {
            return this.show_type;
        }

        public void setFilter(String str) {
            this.filter = str;
        }

        public void setIco(String str) {
            this.ico = str;
        }

        public void setName(String str) {
            this.name = str;
        }

        public void setShow_type(String str) {
            this.show_type = str;
        }
    }

    @Override // p005b.p067b.p068a.p069a.p070a.p074j.InterfaceC1296a
    public int getItemType() {
        return this.style;
    }
}

package com.jbzd.media.movecartoons.bean.response;

import com.jbzd.media.movecartoons.bean.response.home.AdBean;
import java.util.ArrayList;

/* loaded from: classes2.dex */
public class HotSearch {
    public ArrayList<AdBean> ads;
    public ArrayList<HotWord> items;

    public static class HotWord {
        public String click;

        /* renamed from: id */
        public String f9961id;
        public String name;
    }
}

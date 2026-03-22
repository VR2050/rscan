package com.jbzd.media.movecartoons.bean.response;

import java.util.ArrayList;

/* loaded from: classes2.dex */
public class ScoreBean {
    public ArrayList<ExchangeItem> exchange_items;
    public SimpleUser user;

    public static class ExchangeItem {
        public String day;
        public String group;
        public int num;
    }
}

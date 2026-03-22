package com.jbzd.media.movecartoons.bean.response;

import java.util.List;

/* loaded from: classes2.dex */
public class FaqBean {
    public List<FaqItem> faq_items;
    public String system_head_img;

    public static class FaqItem {
        public String content;
        public String created_at;

        /* renamed from: id */
        public String f9950id;
        public String title;
    }
}

package com.jbzd.media.movecartoons.bean.response;

import com.jbzd.media.movecartoons.bean.response.FaqBean;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import p005b.p067b.p068a.p069a.p070a.p074j.InterfaceC1296a;

/* loaded from: classes2.dex */
public class ChatMsgBean implements InterfaceC1296a {

    /* renamed from: ME */
    public static final int f9937ME = 1;
    public static final int OTHER = 2;
    public static final int PROBLEM = 3;
    public static final String REQUEST_FAQ = "faq";
    public static final String REQUEST_FAQ_DATING = "faq_dating";
    public static final String REQUEST_FAQ_MONEY = "faq_money";
    public static final String REQUEST_FAQ_NUDE = "faq_nude";
    public static final String SERVICE_CHAT_ID = "-3";
    public static final String SERVICE_ID = "-1";
    public static final String SERVICE_RECHARGE_ID = "-5";
    public static final String SERVICE_SEX_ID = "-4";
    public static final String TYPE_IMAGE = "image";
    public static final String TYPE_TEXT = "text";
    public String content;
    public String ext;
    private List<FaqBean.FaqItem> faq;
    public FaqBean faqBean;
    public String headico;

    /* renamed from: id */
    public String f9938id;
    public String is_my;
    public String link;
    private List<MessageBean> message;
    public String nickname;
    private String system_head_img;
    public String time_label;
    public String type;
    public String user_id;

    public static class MessageBean implements InterfaceC1296a {
        public String content;
        public String ext;
        public FaqBean faqBean;
        public String head_img;

        /* renamed from: id */
        public String f9939id;
        public String is_my;
        public String nickname;
        private String system_head_img;
        public String time_label = "";
        public String type;
        public String user_id;

        @Override // p005b.p067b.p068a.p069a.p070a.p074j.InterfaceC1296a
        public int getItemType() {
            String str = this.is_my;
            boolean z = false;
            if (!(str == null || str.length() == 0) && Intrinsics.areEqual(str, "y")) {
                z = true;
            }
            return z ? 1 : 2;
        }

        public boolean isImage() {
            return "image".equals(this.type);
        }
    }

    public List<FaqBean.FaqItem> getFaq() {
        return this.faq;
    }

    @Override // p005b.p067b.p068a.p069a.p070a.p074j.InterfaceC1296a
    public int getItemType() {
        if (this.faqBean != null) {
            return 3;
        }
        String str = this.is_my;
        boolean z = false;
        if (!(str == null || str.length() == 0) && Intrinsics.areEqual(str, "y")) {
            z = true;
        }
        return z ? 1 : 2;
    }

    public List<MessageBean> getMessage() {
        return this.message;
    }

    public String getSystem_head_img() {
        return this.system_head_img;
    }

    public boolean isImage() {
        return "image".equals(this.type);
    }

    public void setFaq(List<FaqBean.FaqItem> list) {
        this.faq = list;
    }

    public void setMessage(List<MessageBean> list) {
        this.message = list;
    }

    public void setSystem_head_img(String str) {
        this.system_head_img = str;
    }
}

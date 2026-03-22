package com.jbzd.media.movecartoons.bean.response;

import java.util.ArrayList;

/* loaded from: classes2.dex */
public class WelfareBean {
    public SignBean sign;
    public ArrayList<TaskItem> task_items;
    public String task_tips;
    public SimpleUser user;

    public static class SignBean {
        public String has_done;
        public String info;
        public ArrayList<SignItem> items;
    }

    public static class SignItem {
        public String day;
        public String has_done;
        public String name;
        public String num;
    }

    public static class TaskItem {
        public String description;

        /* renamed from: id */
        public String f10003id;
        public String link;
        public String name;
        public String status;
        public String status_text;
        public String type;
    }
}

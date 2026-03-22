package com.jbzd.media.movecartoons.bean.response;

import com.jbzd.media.movecartoons.bean.response.tag.TagBean;
import java.io.Serializable;
import java.util.List;

/* loaded from: classes2.dex */
public class PostDetailBean implements Serializable {
    public String can_view;
    public List<TagBean> categories;
    public String city;
    public String click;
    public String comment;
    public String content;
    public String deny_msg;
    public String favorite;
    public List<FilesBean> files;
    public String has_favorite;
    public String has_love;

    /* renamed from: id */
    public String f9974id;
    public String is_hot;
    public String is_own;
    public String is_top;
    public List<GamesBean> links;
    public String love = "";
    public String money;
    public String pay_type;
    public String position;
    public String province;
    public String status;
    public String status_text;
    public String time;
    public String title;
    public String type;
    public UserBean user;

    public static class CategoriesBean {

        /* renamed from: id */
        public String f9975id;
        public String name;
    }

    public static class FilesBean implements Serializable {
        public String can_download;
        public String ico;
        public String image;
        public String tips;
        public String type;
        public String video_link;
    }

    public static class GamesBean implements Serializable {
        public String name;
        public String url;
    }

    public static class UserBean {

        /* renamed from: id */
        public String f9976id;
        public String img;
        public String is_follow;
        public String is_up;
        public String is_vip;
        public String nickname;
        public String sex;
    }
}

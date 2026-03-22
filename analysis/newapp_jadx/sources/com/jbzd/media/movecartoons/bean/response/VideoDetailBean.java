package com.jbzd.media.movecartoons.bean.response;

import com.jbzd.media.movecartoons.bean.response.home.AdBean;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public class VideoDetailBean extends VideoItemBean implements Serializable {
    public String categories;
    public String comment;
    public String comment_count;
    public String description;
    public String favorite;
    public String has_favorite;
    public String has_love;
    public String ico;
    public String is_more_link;
    public List<MultiLinks> links;
    public String play_ad_auto_jump;
    public String play_ad_show_time;
    public List<AdBean> play_ads;
    public String play_error;
    public String played_duration;
    public String position;
    public List<VideoDetailBean> relation_video = new ArrayList();
    public String score;
    public ShareInfoBean share_info;
    public UserBean user;

    public static class MultiLinks implements Serializable {

        /* renamed from: id */
        public String f9994id;
        public String is_select = "";
        public String name;
    }

    public static class PlayLinksBean implements Serializable {

        /* renamed from: id */
        public String f9995id;
        public String m3u8_url;
        public String name;
        public String preview_m3u8_url;
    }

    public static class ShareInfoBean implements Serializable {
        public String share_code;
        public String share_content;
        public String share_job_desc;
        public String share_link;
        public String share_num;
        public String share_user_id;
        public String site_url;
    }

    public static class UserBean implements Serializable {
        public String balance;

        /* renamed from: id */
        public String f9996id;
        public String img;
        public String is_vip;
        public String level;
        public String nickname;
        public String username;
    }

    public static class VideoUserBean implements Serializable {

        /* renamed from: id */
        public String f9997id;
        public String img;
        public String is_follow;
        public String is_up;
        public String is_vip;
        public String nickname;
        public String sex;
    }
}

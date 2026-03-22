package com.jbzd.media.movecartoons.bean.response;

import com.jbzd.media.movecartoons.bean.response.PostHomeResponse;
import java.io.Serializable;
import java.util.List;

/* loaded from: classes2.dex */
public class PostCategoryDetailBean implements Serializable {
    public String block_id;
    public String block_name;
    public CatInfoBean cat_info;
    public List<CatInfoBean> categories;
    public List<PostHomeResponse.OrdersBean> orders;

    public static class CatInfoBean {
        public String block_id;
        public String block_name;
        public String description;
        public String follow;
        public String has_follow;

        /* renamed from: id */
        public String f9973id;
        public String img;
        public String name;
        public String position;
        public String post_click;
        public String post_count;
    }
}

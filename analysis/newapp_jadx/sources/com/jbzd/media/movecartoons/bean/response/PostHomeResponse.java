package com.jbzd.media.movecartoons.bean.response;

import com.jbzd.media.movecartoons.bean.response.home.AdBean;
import java.io.Serializable;
import java.util.List;

/* loaded from: classes2.dex */
public class PostHomeResponse implements Serializable {
    public List<AdBean> banner;
    public String block_id;
    public String block_name;
    public List<CategoriesBean> categories;
    public List<OrdersBean> orders;
    public List<HLSFollowerBean> up_items;

    public static class CategoriesBean implements Serializable {
        public String block_id;
        public String block_name;
        public String description;
        public String follow;
        public String has_follow;

        /* renamed from: id */
        public String f9977id;
        public String img;
        public String name;
        public String position;
        public String post_click;
        public String post_count;

        public String getBlock_id() {
            return this.block_id;
        }

        public String getBlock_name() {
            return this.block_name;
        }

        public String getDescription() {
            return this.description;
        }

        public String getFollow() {
            return this.follow;
        }

        public String getHas_follow() {
            return this.has_follow;
        }

        public String getId() {
            return this.f9977id;
        }

        public String getImg() {
            return this.img;
        }

        public String getName() {
            return this.name;
        }

        public String getPosition() {
            return this.position;
        }

        public String getPost_click() {
            return this.post_click;
        }

        public String getPost_count() {
            return this.post_count;
        }

        public void setBlock_id(String str) {
            this.block_id = str;
        }

        public void setBlock_name(String str) {
            this.block_name = str;
        }

        public void setDescription(String str) {
            this.description = str;
        }

        public void setFollow(String str) {
            this.follow = str;
        }

        public void setHas_follow(String str) {
            this.has_follow = str;
        }

        public void setId(String str) {
            this.f9977id = str;
        }

        public void setImg(String str) {
            this.img = str;
        }

        public void setName(String str) {
            this.name = str;
        }

        public void setPosition(String str) {
            this.position = str;
        }

        public void setPost_click(String str) {
            this.post_click = str;
        }

        public void setPost_count(String str) {
            this.post_count = str;
        }
    }

    public static class FilterBean implements Serializable {
        public String position = "";
        public String is_follow = "";
        public String order = "";
    }

    public static class HLSFollowerBean {
        public String fans;
        public String follow;
        public String has_follow;
        public String img;
        public String is_up;
        public String is_vip;
        public String nickname;
        public String sing;

        /* renamed from: id */
        public String f9978id = "";
        public String user_id = "";
    }

    public static class OrdersBean implements Serializable {
        private String filter;
        private String name;

        public String getFilter() {
            return this.filter;
        }

        public String getName() {
            return this.name;
        }

        public void setFilter(String str) {
            this.filter = str;
        }

        public void setName(String str) {
            this.name = str;
        }
    }

    public String getBlock_id() {
        return this.block_id;
    }

    public String getBlock_name() {
        return this.block_name;
    }

    public List<CategoriesBean> getCategories() {
        return this.categories;
    }

    public List<OrdersBean> getOrders() {
        return this.orders;
    }

    public void setBlock_id(String str) {
        this.block_id = str;
    }

    public void setBlock_name(String str) {
        this.block_name = str;
    }

    public void setCategories(List<CategoriesBean> list) {
        this.categories = list;
    }

    public void setOrders(List<OrdersBean> list) {
        this.orders = list;
    }
}

package com.jbzd.media.movecartoons.bean.response;

import java.io.Serializable;
import java.util.List;

/* loaded from: classes2.dex */
public class PostBlockListBean implements Serializable {
    private String block_id;
    private String block_name;
    private List<CategoriesBean> categories;

    public static class CategoriesBean {
        private String block_id;
        private String block_name;
        private String description;
        private String follow;
        private String has_follow;

        /* renamed from: id */
        private String f9972id;
        private String img;
        private String name;
        private String position;
        private String post_click;
        private String post_count;

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
            return this.f9972id;
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
            this.f9972id = str;
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

    public String getBlock_id() {
        return this.block_id;
    }

    public String getBlock_name() {
        return this.block_name;
    }

    public List<CategoriesBean> getCategories() {
        return this.categories;
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
}

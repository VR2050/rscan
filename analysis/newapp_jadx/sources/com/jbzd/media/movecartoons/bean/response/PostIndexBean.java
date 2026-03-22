package com.jbzd.media.movecartoons.bean.response;

import com.jbzd.media.movecartoons.bean.response.home.AdBean;
import java.util.List;

/* loaded from: classes2.dex */
public class PostIndexBean {
    private List<AdBean> ads;
    private List<CategoriesBean> categories;
    private List<Types> types;
    private UserInfoBean user;

    public static class Types {

        /* renamed from: id */
        private String f9979id;
        private String name;

        public String getId() {
            return this.f9979id;
        }

        public String getName() {
            return this.name;
        }

        public void setId(String str) {
            this.f9979id = str;
        }

        public void setName(String str) {
            this.name = str;
        }
    }

    public List<AdBean> getAds() {
        return this.ads;
    }

    public List<CategoriesBean> getCategories() {
        return this.categories;
    }

    public List<Types> getTypes() {
        return this.types;
    }

    public UserInfoBean getUser() {
        return this.user;
    }

    public void setAds(List<AdBean> list) {
        this.ads = list;
    }

    public void setCategories(List<CategoriesBean> list) {
        this.categories = list;
    }

    public void setTypes(List<Types> list) {
        this.types = list;
    }

    public void setUser(UserInfoBean userInfoBean) {
        this.user = userInfoBean;
    }
}

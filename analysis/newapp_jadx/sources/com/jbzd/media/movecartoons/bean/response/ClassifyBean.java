package com.jbzd.media.movecartoons.bean.response;

import com.jbzd.media.movecartoons.bean.response.tag.TagBean;
import java.util.List;

/* loaded from: classes2.dex */
public class ClassifyBean {
    private List<CategoriesBean> categories;
    private List<TagBean> tags;

    public List<CategoriesBean> getCategories() {
        return this.categories;
    }

    public List<TagBean> getTags() {
        return this.tags;
    }

    public void setCategories(List<CategoriesBean> list) {
        this.categories = list;
    }

    public void setTags(List<TagBean> list) {
        this.tags = list;
    }
}

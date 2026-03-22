package com.jbzd.media.movecartoons.bean.response;

import com.jbzd.media.movecartoons.bean.response.tag.TagBean;
import java.util.List;

/* loaded from: classes2.dex */
public class PostAddBean {
    private List<TagBean> tags;
    private String tips;

    public List<TagBean> getTags() {
        return this.tags;
    }

    public String getTips() {
        return this.tips;
    }

    public void setTags(List<TagBean> list) {
        this.tags = list;
    }

    public void setTips(String str) {
        this.tips = str;
    }
}

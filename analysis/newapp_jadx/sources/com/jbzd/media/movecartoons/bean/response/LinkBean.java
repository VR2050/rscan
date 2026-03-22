package com.jbzd.media.movecartoons.bean.response;

import java.io.Serializable;
import java.util.List;

/* loaded from: classes2.dex */
public class LinkBean implements Serializable, Cloneable {

    /* renamed from: id */
    private String f9966id;
    private String is_vip;
    private String link;
    private List<LinkData> links;
    private String name;

    public class LinkData implements Serializable, Cloneable {
        private String code;
        private String link;
        private String name;

        public LinkData() {
        }

        public String getCode() {
            return this.code;
        }

        public String getLink() {
            return this.link;
        }

        public String getName() {
            return this.name;
        }

        public void setCode(String str) {
            this.code = str;
        }

        public void setLink(String str) {
            this.link = str;
        }

        public void setName(String str) {
            this.name = str;
        }
    }

    public String getId() {
        return this.f9966id;
    }

    public String getIs_vip() {
        return this.is_vip;
    }

    public String getLink() {
        return this.link;
    }

    public List<LinkData> getLinks() {
        return this.links;
    }

    public String getName() {
        return this.name;
    }

    public void setId(String str) {
        this.f9966id = str;
    }

    public void setIs_vip(String str) {
        this.is_vip = str;
    }

    public void setLink(String str) {
        this.link = str;
    }

    public void setLinks(List<LinkData> list) {
        this.links = list;
    }

    public void setName(String str) {
        this.name = str;
    }
}

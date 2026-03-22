package com.jbzd.media.movecartoons.bean.response;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public class LibraryBean implements Serializable, Cloneable {
    public List<FilterData> one = new ArrayList();
    public List<FilterData> two = new ArrayList();
    public List<FilterData> three = new ArrayList();
    public List<FilterData> four = new ArrayList();

    public List<FilterData> getFour() {
        return this.four;
    }

    public List<FilterData> getOne() {
        return this.one;
    }

    public List<FilterData> getThree() {
        return this.three;
    }

    public List<FilterData> getTwo() {
        return this.two;
    }

    public void setFour(List<FilterData> list) {
        this.four = list;
    }

    public void setOne(List<FilterData> list) {
        this.one = list;
    }

    public void setThree(List<FilterData> list) {
        this.three = list;
    }

    public void setTwo(List<FilterData> list) {
        this.two = list;
    }

    public class LibraryBeanData implements Serializable {
        public String code;
        public boolean isSelected;
        public String name;
        public String value;
        public Integer watch_limit;

        public LibraryBeanData(String str, String str2, String str3) {
            this.isSelected = false;
            this.watch_limit = 0;
            this.name = str;
            this.value = str2;
            this.code = str3;
        }

        public String getCode() {
            return this.code;
        }

        public String getName() {
            return this.name;
        }

        public String getValue() {
            return this.value;
        }

        public void setCode(String str) {
            this.code = str;
        }

        public void setName(String str) {
            this.name = str;
        }

        public void setValue(String str) {
            this.value = str;
        }

        public LibraryBeanData(String str, String str2, String str3, boolean z) {
            this.isSelected = false;
            this.watch_limit = 0;
            this.name = str;
            this.value = str2;
            this.code = str3;
            this.isSelected = z;
        }
    }
}

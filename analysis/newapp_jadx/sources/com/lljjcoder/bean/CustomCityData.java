package com.lljjcoder.bean;

import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public class CustomCityData {

    /* renamed from: id */
    private String f10196id;
    private List<CustomCityData> list = new ArrayList();
    private String name;

    public CustomCityData() {
    }

    public String getId() {
        return this.f10196id;
    }

    public List<CustomCityData> getList() {
        return this.list;
    }

    public String getName() {
        return this.name;
    }

    public void setId(String str) {
        this.f10196id = str;
    }

    public void setList(List<CustomCityData> list) {
        this.list = list;
    }

    public void setName(String str) {
        this.name = str;
    }

    public String toString() {
        return this.name;
    }

    public CustomCityData(String str, String str2) {
        this.f10196id = str;
        this.name = str2;
    }
}

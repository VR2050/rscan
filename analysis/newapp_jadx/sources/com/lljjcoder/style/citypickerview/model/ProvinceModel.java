package com.lljjcoder.style.citypickerview.model;

import java.util.List;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes2.dex */
public class ProvinceModel {
    private List<CityModel> cityList;
    private String name;

    public ProvinceModel() {
    }

    public List<CityModel> getCityList() {
        return this.cityList;
    }

    public String getName() {
        return this.name;
    }

    public void setCityList(List<CityModel> list) {
        this.cityList = list;
    }

    public void setName(String str) {
        this.name = str;
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("ProvinceModel [name=");
        m586H.append(this.name);
        m586H.append(", cityList=");
        m586H.append(this.cityList);
        m586H.append("]");
        return m586H.toString();
    }

    public ProvinceModel(String str, List<CityModel> list) {
        this.name = str;
        this.cityList = list;
    }
}

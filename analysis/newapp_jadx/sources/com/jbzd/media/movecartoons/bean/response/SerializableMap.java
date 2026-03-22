package com.jbzd.media.movecartoons.bean.response;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;

/* loaded from: classes2.dex */
public class SerializableMap implements Serializable {
    private HashMap<String, ArrayList<FilterData>> map;

    public HashMap<String, ArrayList<FilterData>> getMap() {
        return this.map;
    }

    public void setMap(HashMap<String, ArrayList<FilterData>> hashMap) {
        this.map = hashMap;
    }
}

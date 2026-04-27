package com.RNFetchBlob;

import c1.L;
import com.facebook.react.bridge.ReactApplicationContext;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
public class e implements L {
    @Override // c1.L
    public List e(ReactApplicationContext reactApplicationContext) {
        ArrayList arrayList = new ArrayList();
        arrayList.add(new RNFetchBlob(reactApplicationContext));
        return arrayList;
    }

    @Override // c1.L
    public List f(ReactApplicationContext reactApplicationContext) {
        return Collections.emptyList();
    }
}

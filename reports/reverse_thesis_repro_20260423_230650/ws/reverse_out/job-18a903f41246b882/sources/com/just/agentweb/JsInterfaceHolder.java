package com.just.agentweb;

import java.util.Map;

/* JADX INFO: loaded from: classes3.dex */
public interface JsInterfaceHolder {
    JsInterfaceHolder addJavaObject(String str, Object obj);

    JsInterfaceHolder addJavaObjects(Map<String, Object> map);

    boolean checkObject(Object obj);
}

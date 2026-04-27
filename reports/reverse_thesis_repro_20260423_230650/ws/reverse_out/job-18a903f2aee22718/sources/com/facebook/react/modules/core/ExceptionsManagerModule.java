package com.facebook.react.modules.core;

import com.facebook.fbreact.specs.NativeExceptionsManagerSpec;
import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.JavaOnlyMap;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.common.JavascriptException;
import j1.e;
import t2.j;
import u1.InterfaceC0703a;

/* JADX INFO: loaded from: classes.dex */
@InterfaceC0703a(name = NativeExceptionsManagerSpec.NAME)
public class ExceptionsManagerModule extends NativeExceptionsManagerSpec {
    private final e devSupportManager;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ExceptionsManagerModule(e eVar) {
        super(null);
        j.f(eVar, "devSupportManager");
        this.devSupportManager = eVar;
    }

    @Override // com.facebook.fbreact.specs.NativeExceptionsManagerSpec
    public void dismissRedbox() {
        if (this.devSupportManager.m()) {
            this.devSupportManager.o();
        }
    }

    @Override // com.facebook.fbreact.specs.NativeExceptionsManagerSpec
    public void reportException(ReadableMap readableMap) {
        j.f(readableMap, "data");
        String string = readableMap.getString("message");
        if (string == null) {
            string = "";
        }
        ReadableArray array = readableMap.getArray("stack");
        if (array == null) {
            array = Arguments.createArray();
        }
        boolean z3 = readableMap.hasKey("isFatal") ? readableMap.getBoolean("isFatal") : false;
        String strA = S1.a.a(readableMap);
        if (z3) {
            j.c(array);
            JavascriptException javascriptException = new JavascriptException(S1.b.a(string, array));
            javascriptException.a(strA);
            throw javascriptException;
        }
        j.c(array);
        Y.a.m("ReactNative", S1.b.a(string, array));
        if (strA != null) {
            Y.a.c("ReactNative", "extraData: %s", strA);
        }
    }

    @Override // com.facebook.fbreact.specs.NativeExceptionsManagerSpec
    public void reportFatalException(String str, ReadableArray readableArray, double d3) {
        JavaOnlyMap javaOnlyMap = new JavaOnlyMap();
        javaOnlyMap.putString("message", str);
        javaOnlyMap.putArray("stack", readableArray);
        javaOnlyMap.putInt("id", (int) d3);
        javaOnlyMap.putBoolean("isFatal", true);
        reportException(javaOnlyMap);
    }

    @Override // com.facebook.fbreact.specs.NativeExceptionsManagerSpec
    public void reportSoftException(String str, ReadableArray readableArray, double d3) {
        JavaOnlyMap javaOnlyMap = new JavaOnlyMap();
        javaOnlyMap.putString("message", str);
        javaOnlyMap.putArray("stack", readableArray);
        javaOnlyMap.putInt("id", (int) d3);
        javaOnlyMap.putBoolean("isFatal", false);
        reportException(javaOnlyMap);
    }
}

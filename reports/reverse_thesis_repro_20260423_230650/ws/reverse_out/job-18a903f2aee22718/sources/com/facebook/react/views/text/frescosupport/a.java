package com.facebook.react.views.text.frescosupport;

import Y1.p;
import android.content.Context;
import android.net.Uri;
import com.facebook.react.bridge.Dynamic;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.ReadableType;
import java.util.Locale;
import p0.AbstractC0643b;
import q.g;

/* JADX INFO: loaded from: classes.dex */
class a extends X1.a {

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    private Uri f8074A;

    /* JADX INFO: renamed from: B, reason: collision with root package name */
    private ReadableMap f8075B;

    /* JADX INFO: renamed from: C, reason: collision with root package name */
    private final AbstractC0643b f8076C;

    /* JADX INFO: renamed from: D, reason: collision with root package name */
    private final Object f8077D;

    /* JADX INFO: renamed from: F, reason: collision with root package name */
    private String f8079F;

    /* JADX INFO: renamed from: E, reason: collision with root package name */
    private float f8078E = Float.NaN;

    /* JADX INFO: renamed from: G, reason: collision with root package name */
    private float f8080G = Float.NaN;

    /* JADX INFO: renamed from: H, reason: collision with root package name */
    private int f8081H = 0;

    public a(AbstractC0643b abstractC0643b, Object obj) {
        this.f8076C = abstractC0643b;
        this.f8077D = obj;
    }

    private static Uri A1(Context context, String str) {
        if (str == null || str.isEmpty()) {
            return null;
        }
        return new Uri.Builder().scheme("res").path(String.valueOf(context.getResources().getIdentifier(str.toLowerCase(Locale.getDefault()).replace("-", "_"), "drawable", context.getPackageName()))).build();
    }

    public Uri B1() {
        return this.f8074A;
    }

    @Override // com.facebook.react.uimanager.C0467r0, com.facebook.react.uimanager.InterfaceC0466q0
    public boolean R() {
        return true;
    }

    @K1.a(name = "headers")
    public void setHeaders(ReadableMap readableMap) {
        this.f8075B = readableMap;
    }

    @Override // com.facebook.react.uimanager.U
    public void setHeight(Dynamic dynamic) {
        if (dynamic.getType() == ReadableType.Number) {
            this.f8080G = (float) dynamic.asDouble();
        } else {
            Y.a.I("ReactNative", "Inline images must not have percentage based height");
            this.f8080G = Float.NaN;
        }
    }

    @K1.a(name = "resizeMode")
    public void setResizeMode(String str) {
        this.f8079F = str;
    }

    @K1.a(name = "src")
    public void setSource(ReadableArray readableArray) {
        Uri uriA1 = null;
        String string = (readableArray == null || readableArray.size() == 0 || readableArray.getType(0) != ReadableType.Map) ? null : ((ReadableMap) g.f(readableArray.getMap(0))).getString("uri");
        if (string != null) {
            try {
                Uri uri = Uri.parse(string);
                if (uri.getScheme() != null) {
                    uriA1 = uri;
                }
            } catch (Exception unused) {
            }
            if (uriA1 == null) {
                uriA1 = A1(l(), string);
            }
        }
        if (uriA1 != this.f8074A) {
            y0();
        }
        this.f8074A = uriA1;
    }

    @K1.a(customType = "Color", name = "tintColor")
    public void setTintColor(int i3) {
        this.f8081H = i3;
    }

    @Override // com.facebook.react.uimanager.U
    public void setWidth(Dynamic dynamic) {
        if (dynamic.getType() == ReadableType.Number) {
            this.f8078E = (float) dynamic.asDouble();
        } else {
            Y.a.I("ReactNative", "Inline images must not have percentage based width");
            this.f8078E = Float.NaN;
        }
    }

    @Override // X1.a
    public p w1() {
        return new b(l().getResources(), (int) Math.ceil(this.f8080G), (int) Math.ceil(this.f8078E), this.f8081H, B1(), z1(), y1(), x1(), this.f8079F);
    }

    public Object x1() {
        return this.f8077D;
    }

    public AbstractC0643b y1() {
        return this.f8076C;
    }

    public ReadableMap z1() {
        return this.f8075B;
    }
}

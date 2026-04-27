package com.facebook.react.modules.network;

import android.webkit.CookieManager;
import android.webkit.ValueCallback;
import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.ReactContext;
import i2.AbstractC0586n;
import i2.D;
import java.net.CookieHandler;
import java.net.URI;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class d extends CookieHandler {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static final a f7130b = new a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private CookieManager f7131a;

    private static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final boolean b(String str) {
            return z2.g.j(str, "Set-cookie", true) || z2.g.j(str, "Set-cookie2", true);
        }

        private a() {
        }
    }

    public d() {
    }

    private final void b(String str, String str2) {
        CookieManager cookieManagerG = g();
        if (cookieManagerG != null) {
            cookieManagerG.setCookie(str, str2, null);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void e(Callback callback, Boolean bool) {
        callback.invoke(bool);
    }

    private final CookieManager g() {
        if (this.f7131a == null) {
            try {
                this.f7131a = CookieManager.getInstance();
            } catch (IllegalArgumentException | Exception unused) {
                return null;
            }
        }
        return this.f7131a;
    }

    public final void c(String str, List list) {
        t2.j.f(str, "url");
        t2.j.f(list, "cookies");
        Iterator it = list.iterator();
        while (it.hasNext()) {
            b(str, (String) it.next());
        }
        CookieManager cookieManagerG = g();
        if (cookieManagerG != null) {
            cookieManagerG.flush();
        }
    }

    public final void d(final Callback callback) {
        t2.j.f(callback, "callback");
        CookieManager cookieManagerG = g();
        if (cookieManagerG != null) {
            cookieManagerG.removeAllCookies(new ValueCallback() { // from class: com.facebook.react.modules.network.c
                @Override // android.webkit.ValueCallback
                public final void onReceiveValue(Object obj) {
                    d.e(callback, (Boolean) obj);
                }
            });
        }
    }

    public final void f() {
    }

    @Override // java.net.CookieHandler
    public Map get(URI uri, Map map) {
        t2.j.f(uri, "uri");
        t2.j.f(map, "headers");
        CookieManager cookieManagerG = g();
        String cookie = cookieManagerG != null ? cookieManagerG.getCookie(uri.toString()) : null;
        return (cookie == null || cookie.length() == 0) ? D.f() : D.d(h2.n.a("Cookie", AbstractC0586n.b(cookie)));
    }

    @Override // java.net.CookieHandler
    public void put(URI uri, Map map) {
        t2.j.f(uri, "uri");
        t2.j.f(map, "headers");
        String string = uri.toString();
        t2.j.e(string, "toString(...)");
        for (Map.Entry entry : map.entrySet()) {
            String str = (String) entry.getKey();
            List list = (List) entry.getValue();
            if (f7130b.b(str)) {
                c(string, list);
            }
        }
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public d(ReactContext reactContext) {
        this();
        t2.j.f(reactContext, "reactContext");
    }
}

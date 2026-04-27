package com.zhy.http.okhttp.cookie.store;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import okhttp3.Cookie;
import okhttp3.HttpUrl;

/* JADX INFO: loaded from: classes3.dex */
public class MemoryCookieStore implements CookieStore {
    private final HashMap<String, List<Cookie>> allCookies = new HashMap<>();

    @Override // com.zhy.http.okhttp.cookie.store.CookieStore
    public void add(HttpUrl url, List<Cookie> cookies) {
        List<Cookie> oldCookies = this.allCookies.get(url.host());
        if (oldCookies != null) {
            Iterator<Cookie> itNew = cookies.iterator();
            Iterator<Cookie> itOld = oldCookies.iterator();
            while (itNew.hasNext()) {
                String va = itNew.next().name();
                while (va != null && itOld.hasNext()) {
                    String v = itOld.next().name();
                    if (v != null && va.equals(v)) {
                        itOld.remove();
                    }
                }
            }
            oldCookies.addAll(cookies);
            return;
        }
        this.allCookies.put(url.host(), cookies);
    }

    @Override // com.zhy.http.okhttp.cookie.store.CookieStore
    public List<Cookie> get(HttpUrl uri) {
        List<Cookie> cookies = this.allCookies.get(uri.host());
        if (cookies == null) {
            List<Cookie> cookies2 = new ArrayList<>();
            this.allCookies.put(uri.host(), cookies2);
            return cookies2;
        }
        return cookies;
    }

    @Override // com.zhy.http.okhttp.cookie.store.CookieStore
    public boolean removeAll() {
        this.allCookies.clear();
        return true;
    }

    @Override // com.zhy.http.okhttp.cookie.store.CookieStore
    public List<Cookie> getCookies() {
        List<Cookie> cookies = new ArrayList<>();
        Set<String> httpUrls = this.allCookies.keySet();
        for (String url : httpUrls) {
            cookies.addAll(this.allCookies.get(url));
        }
        return cookies;
    }

    @Override // com.zhy.http.okhttp.cookie.store.CookieStore
    public boolean remove(HttpUrl uri, Cookie cookie) {
        List<Cookie> cookies = this.allCookies.get(uri.host());
        if (cookie != null) {
            return cookies.remove(cookie);
        }
        return false;
    }
}

package com.alipay.android.phone.mrpc.core;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import org.apache.http.Header;

/* renamed from: com.alipay.android.phone.mrpc.core.o */
/* loaded from: classes.dex */
public final class C3155o extends AbstractC3160t {

    /* renamed from: b */
    private String f8567b;

    /* renamed from: c */
    private byte[] f8568c;

    /* renamed from: g */
    private boolean f8572g;

    /* renamed from: e */
    private ArrayList<Header> f8570e = new ArrayList<>();

    /* renamed from: f */
    private Map<String, String> f8571f = new HashMap();

    /* renamed from: d */
    private String f8569d = "application/x-www-form-urlencoded";

    public C3155o(String str) {
        this.f8567b = str;
    }

    /* renamed from: a */
    public final String m3687a() {
        return this.f8567b;
    }

    /* renamed from: a */
    public final void m3688a(String str) {
        this.f8569d = str;
    }

    /* renamed from: a */
    public final void m3689a(String str, String str2) {
        if (this.f8571f == null) {
            this.f8571f = new HashMap();
        }
        this.f8571f.put(str, str2);
    }

    /* renamed from: a */
    public final void m3690a(Header header) {
        this.f8570e.add(header);
    }

    /* renamed from: a */
    public final void m3691a(boolean z) {
        this.f8572g = z;
    }

    /* renamed from: a */
    public final void m3692a(byte[] bArr) {
        this.f8568c = bArr;
    }

    /* renamed from: b */
    public final String m3693b(String str) {
        Map<String, String> map = this.f8571f;
        if (map == null) {
            return null;
        }
        return map.get(str);
    }

    /* renamed from: b */
    public final byte[] m3694b() {
        return this.f8568c;
    }

    /* renamed from: c */
    public final String m3695c() {
        return this.f8569d;
    }

    /* renamed from: d */
    public final ArrayList<Header> m3696d() {
        return this.f8570e;
    }

    /* renamed from: e */
    public final boolean m3697e() {
        return this.f8572g;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || C3155o.class != obj.getClass()) {
            return false;
        }
        C3155o c3155o = (C3155o) obj;
        byte[] bArr = this.f8568c;
        if (bArr == null) {
            if (c3155o.f8568c != null) {
                return false;
            }
        } else if (!bArr.equals(c3155o.f8568c)) {
            return false;
        }
        String str = this.f8567b;
        String str2 = c3155o.f8567b;
        if (str == null) {
            if (str2 != null) {
                return false;
            }
        } else if (!str.equals(str2)) {
            return false;
        }
        return true;
    }

    public final int hashCode() {
        Map<String, String> map = this.f8571f;
        int hashCode = ((map == null || !map.containsKey("id")) ? 1 : this.f8571f.get("id").hashCode() + 31) * 31;
        String str = this.f8567b;
        return hashCode + (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        return String.format("Url : %s,HttpHeader: %s", this.f8567b, this.f8570e);
    }
}

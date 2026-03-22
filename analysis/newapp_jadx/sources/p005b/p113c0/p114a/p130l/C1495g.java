package p005b.p113c0.p114a.p130l;

import com.alibaba.fastjson.support.spring.FastJsonJsonView;
import com.google.android.material.shadow.ShadowDrawableWrapper;
import com.luck.picture.lib.config.PictureMimeType;
import java.io.Serializable;
import java.nio.charset.Charset;
import java.util.Collections;
import java.util.Map;
import p005b.p113c0.p114a.p115g.C1416b;
import p005b.p113c0.p114a.p115g.C1417c;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* renamed from: b.c0.a.l.g */
/* loaded from: classes2.dex */
public class C1495g extends C1496h implements Serializable {

    /* renamed from: h */
    public static final C1495g f1507h = m568k("*/*");

    /* renamed from: i */
    public static final C1495g f1508i;

    /* renamed from: j */
    public static final C1495g f1509j;

    /* renamed from: k */
    public static final C1495g f1510k;

    static {
        m568k("application/json");
        m568k(FastJsonJsonView.DEFAULT_CONTENT_TYPE);
        m568k("application/xml");
        m568k("application/xml;charset=UTF-8");
        m568k("application/atom+xml");
        f1508i = m568k("application/x-www-form-urlencoded");
        f1509j = m568k("application/octet-stream");
        m568k("application/rss+xml");
        m568k("application/xhtml+xml");
        m568k("application/pdf");
        m568k("image/gif");
        m568k("image/jpeg");
        m568k(PictureMimeType.PNG_Q);
        m568k("multipart/form-data");
        m568k("text/event-stream");
        m568k("text/html");
        m568k("text/markdown");
        f1510k = m568k("text/plain");
        m568k("text/xml");
    }

    public C1495g(String str, String str2, Charset charset) {
        super(str, str2, Collections.singletonMap("charset", charset.name()));
    }

    /* renamed from: k */
    public static C1495g m568k(String str) {
        try {
            C1496h m571i = C1496h.m571i(str);
            try {
                return new C1495g(m571i.f1512e, m571i.f1513f, m571i.f1514g);
            } catch (IllegalArgumentException e2) {
                throw new C1416b(str, e2.getMessage());
            }
        } catch (C1417c e3) {
            throw new C1416b(e3);
        }
    }

    @Override // p005b.p113c0.p114a.p130l.C1496h
    /* renamed from: a */
    public void mo569a(String str, String str2) {
        super.mo569a(str, str2);
        if ("q".equals(str)) {
            String m578h = m578h(str2);
            double parseDouble = Double.parseDouble(m578h);
            C2354n.m2426R0(parseDouble >= ShadowDrawableWrapper.COS_45 && parseDouble <= 1.0d, C1499a.m639y("Invalid quality value '", m578h, "': should be between 0.0 and 1.0"));
        }
    }

    /* renamed from: j */
    public boolean m570j(C1495g c1495g) {
        if (c1495g == null) {
            return false;
        }
        if (!m577g()) {
            if (!this.f1512e.equals(c1495g.f1512e)) {
                return false;
            }
            if (!this.f1513f.equals(c1495g.f1513f)) {
                if (!m576f()) {
                    return false;
                }
                int indexOf = this.f1513f.indexOf(43);
                if (indexOf != -1) {
                    int indexOf2 = c1495g.f1513f.indexOf(43);
                    if (indexOf2 == -1) {
                        return false;
                    }
                    String substring = this.f1513f.substring(0, indexOf);
                    if (!this.f1513f.substring(indexOf + 1).equals(c1495g.f1513f.substring(indexOf2 + 1)) || !"*".equals(substring)) {
                        return false;
                    }
                }
            }
        }
        return true;
    }

    /* JADX WARN: Illegal instructions before constructor call */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public C1495g(p005b.p113c0.p114a.p130l.C1495g r4, java.nio.charset.Charset r5) {
        /*
            r3 = this;
            java.lang.String r0 = r4.f1512e
            java.lang.String r1 = r4.f1513f
            java.util.Map<java.lang.String, java.lang.String> r4 = r4.f1514g
            java.util.LinkedHashMap r2 = new java.util.LinkedHashMap
            r2.<init>(r4)
            java.lang.String r4 = r5.name()
            java.lang.String r5 = "charset"
            r2.put(r5, r4)
            r3.<init>(r0, r1, r2)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p113c0.p114a.p130l.C1495g.<init>(b.c0.a.l.g, java.nio.charset.Charset):void");
    }

    public C1495g(String str, String str2, Map<String, String> map) {
        super(str, str2, map);
    }
}

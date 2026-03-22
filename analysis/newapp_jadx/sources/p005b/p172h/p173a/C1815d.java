package p005b.p172h.p173a;

import android.text.TextUtils;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.h.a.d */
/* loaded from: classes.dex */
public class C1815d {

    /* renamed from: a */
    public static final Pattern f2780a = Pattern.compile("[R,r]ange:[ ]?bytes=(\\d*)-");

    /* renamed from: b */
    public static final Pattern f2781b = Pattern.compile("GET /(.*) HTTP");

    /* renamed from: c */
    public final String f2782c;

    /* renamed from: d */
    public final long f2783d;

    /* renamed from: e */
    public final boolean f2784e;

    public C1815d(String str) {
        Objects.requireNonNull(str);
        Matcher matcher = f2780a.matcher(str);
        long parseLong = matcher.find() ? Long.parseLong(matcher.group(1)) : -1L;
        this.f2783d = Math.max(0L, parseLong);
        this.f2784e = parseLong >= 0;
        Matcher matcher2 = f2781b.matcher(str);
        if (!matcher2.find()) {
            throw new IllegalArgumentException(C1499a.m639y("Invalid request `", str, "`: url not found!"));
        }
        this.f2782c = matcher2.group(1);
    }

    /* renamed from: a */
    public static C1815d m1160a(InputStream inputStream) {
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream, "UTF-8"));
        StringBuilder sb = new StringBuilder();
        while (true) {
            String readLine = bufferedReader.readLine();
            if (TextUtils.isEmpty(readLine)) {
                return new C1815d(sb.toString());
            }
            sb.append(readLine);
            sb.append('\n');
        }
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("GetRequest{rangeOffset=");
        m586H.append(this.f2783d);
        m586H.append(", partial=");
        m586H.append(this.f2784e);
        m586H.append(", uri='");
        m586H.append(this.f2782c);
        m586H.append('\'');
        m586H.append('}');
        return m586H.toString();
    }
}

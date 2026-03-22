package p005b.p143g.p144a.p147m.p154u;

import android.text.TextUtils;
import androidx.annotation.NonNull;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.g.a.m.u.j */
/* loaded from: classes.dex */
public final class C1668j implements InterfaceC1666h {

    /* renamed from: b */
    public final Map<String, List<InterfaceC1667i>> f2365b;

    /* renamed from: c */
    public volatile Map<String, String> f2366c;

    /* renamed from: b.g.a.m.u.j$a */
    public static final class a {

        /* renamed from: a */
        public static final String f2367a;

        /* renamed from: b */
        public static final Map<String, List<InterfaceC1667i>> f2368b;

        /* renamed from: c */
        public Map<String, List<InterfaceC1667i>> f2369c = f2368b;

        static {
            String property = System.getProperty("http.agent");
            if (!TextUtils.isEmpty(property)) {
                int length = property.length();
                StringBuilder sb = new StringBuilder(property.length());
                for (int i2 = 0; i2 < length; i2++) {
                    char charAt = property.charAt(i2);
                    if ((charAt > 31 || charAt == '\t') && charAt < 127) {
                        sb.append(charAt);
                    } else {
                        sb.append('?');
                    }
                }
                property = sb.toString();
            }
            f2367a = property;
            HashMap hashMap = new HashMap(2);
            if (!TextUtils.isEmpty(property)) {
                hashMap.put("User-Agent", Collections.singletonList(new b(property)));
            }
            f2368b = Collections.unmodifiableMap(hashMap);
        }
    }

    /* renamed from: b.g.a.m.u.j$b */
    public static final class b implements InterfaceC1667i {

        /* renamed from: a */
        @NonNull
        public final String f2370a;

        public b(@NonNull String str) {
            this.f2370a = str;
        }

        @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1667i
        /* renamed from: a */
        public String mo973a() {
            return this.f2370a;
        }

        public boolean equals(Object obj) {
            if (obj instanceof b) {
                return this.f2370a.equals(((b) obj).f2370a);
            }
            return false;
        }

        public int hashCode() {
            return this.f2370a.hashCode();
        }

        public String toString() {
            StringBuilder m586H = C1499a.m586H("StringHeaderFactory{value='");
            m586H.append(this.f2370a);
            m586H.append('\'');
            m586H.append('}');
            return m586H.toString();
        }
    }

    public C1668j(Map<String, List<InterfaceC1667i>> map) {
        this.f2365b = Collections.unmodifiableMap(map);
    }

    @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1666h
    /* renamed from: a */
    public Map<String, String> mo972a() {
        if (this.f2366c == null) {
            synchronized (this) {
                if (this.f2366c == null) {
                    this.f2366c = Collections.unmodifiableMap(m974b());
                }
            }
        }
        return this.f2366c;
    }

    /* renamed from: b */
    public final Map<String, String> m974b() {
        HashMap hashMap = new HashMap();
        for (Map.Entry<String, List<InterfaceC1667i>> entry : this.f2365b.entrySet()) {
            List<InterfaceC1667i> value = entry.getValue();
            StringBuilder sb = new StringBuilder();
            int size = value.size();
            for (int i2 = 0; i2 < size; i2++) {
                String mo973a = value.get(i2).mo973a();
                if (!TextUtils.isEmpty(mo973a)) {
                    sb.append(mo973a);
                    if (i2 != value.size() - 1) {
                        sb.append(',');
                    }
                }
            }
            String sb2 = sb.toString();
            if (!TextUtils.isEmpty(sb2)) {
                hashMap.put(entry.getKey(), sb2);
            }
        }
        return hashMap;
    }

    public boolean equals(Object obj) {
        if (obj instanceof C1668j) {
            return this.f2365b.equals(((C1668j) obj).f2365b);
        }
        return false;
    }

    public int hashCode() {
        return this.f2365b.hashCode();
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("LazyHeaders{headers=");
        m586H.append(this.f2365b);
        m586H.append('}');
        return m586H.toString();
    }
}

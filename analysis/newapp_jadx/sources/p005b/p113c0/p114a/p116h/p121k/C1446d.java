package p005b.p113c0.p114a.p116h.p121k;

import android.text.TextUtils;
import androidx.annotation.NonNull;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import p005b.p113c0.p114a.p130l.InterfaceC1498j;

/* renamed from: b.c0.a.h.k.d */
/* loaded from: classes2.dex */
public class C1446d implements InterfaceC1498j {

    /* renamed from: e */
    public List<a> f1399e = new LinkedList();

    /* renamed from: b.c0.a.h.k.d$a */
    public static class a {

        /* renamed from: a */
        public List<b> f1400a;
    }

    /* renamed from: b.c0.a.h.k.d$b */
    public static class b {

        /* renamed from: a */
        public final String f1401a;

        /* renamed from: b */
        public final boolean f1402b;

        public b(String str, boolean z) {
            this.f1401a = str;
            this.f1402b = z;
        }

        public boolean equals(Object obj) {
            if (obj instanceof b) {
                return this.f1401a.equals(((b) obj).f1401a);
            }
            return false;
        }

        public String toString() {
            return this.f1401a;
        }
    }

    @NonNull
    /* renamed from: b */
    public static String m508b(@NonNull List<b> list) {
        StringBuilder sb = new StringBuilder("");
        if (list.isEmpty()) {
            sb.append("/");
        }
        for (b bVar : list) {
            sb.append("/");
            sb.append(bVar.f1401a);
        }
        return sb.toString();
    }

    @NonNull
    /* renamed from: c */
    public static List<b> m509c(@NonNull String str) {
        int i2;
        LinkedList linkedList = new LinkedList();
        if (!TextUtils.isEmpty(str)) {
            while (str.startsWith("/")) {
                str = str.substring(1);
            }
            while (true) {
                if (!str.endsWith("/")) {
                    break;
                }
                str = str.substring(0, str.length() - 1);
            }
            for (String str2 : str.split("/")) {
                linkedList.add(new b(str2, str2.contains("{")));
            }
        }
        return Collections.unmodifiableList(linkedList);
    }

    /* renamed from: a */
    public void m510a(@NonNull String str) {
        a aVar = new a();
        aVar.f1400a = m509c(str);
        this.f1399e.add(aVar);
    }
}

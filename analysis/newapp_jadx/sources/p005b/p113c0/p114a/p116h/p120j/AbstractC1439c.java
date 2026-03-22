package p005b.p113c0.p114a.p116h.p120j;

import android.text.TextUtils;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import p005b.p113c0.p114a.p116h.InterfaceC1425a;
import p005b.p113c0.p114a.p116h.InterfaceC1428d;
import p005b.p113c0.p114a.p116h.p119i.C1436a;
import p005b.p113c0.p114a.p116h.p121k.C1443a;
import p005b.p113c0.p114a.p116h.p121k.C1444b;
import p005b.p113c0.p114a.p116h.p121k.C1446d;
import p005b.p113c0.p114a.p116h.p122l.InterfaceC1449c;
import p005b.p113c0.p114a.p124i.InterfaceC1457c;
import p005b.p113c0.p114a.p124i.InterfaceC1458d;

/* renamed from: b.c0.a.h.j.c */
/* loaded from: classes2.dex */
public abstract class AbstractC1439c implements InterfaceC1440d {

    /* renamed from: e */
    public final Object f1390e;

    /* renamed from: f */
    public final C1444b f1391f;

    public AbstractC1439c(@NonNull Object obj, @NonNull C1444b c1444b, @NonNull C1443a c1443a) {
        this.f1390e = obj;
        this.f1391f = c1444b;
    }

    @NonNull
    /* renamed from: a */
    public Map<String, String> m503a(@NonNull String str) {
        boolean z;
        List<C1446d.b> m509c = C1446d.m509c(str);
        Iterator<C1446d.a> it = this.f1391f.f1396a.f1399e.iterator();
        while (it.hasNext()) {
            List<C1446d.b> list = it.next().f1400a;
            if (m509c.size() == list.size()) {
                if (C1446d.m508b(list).equals(str)) {
                    return Collections.emptyMap();
                }
                int i2 = 0;
                boolean z2 = false;
                while (true) {
                    if (i2 >= list.size()) {
                        z = true;
                        break;
                    }
                    C1446d.b bVar = list.get(i2);
                    boolean z3 = bVar.f1402b;
                    z2 = z2 || z3;
                    if (!bVar.equals(m509c.get(i2)) && !z3) {
                        z = false;
                        break;
                    }
                    i2++;
                }
                if (z && z2) {
                    HashMap hashMap = new HashMap();
                    for (int i3 = 0; i3 < list.size(); i3++) {
                        C1446d.b bVar2 = list.get(i3);
                        if (bVar2.f1402b) {
                            C1446d.b bVar3 = m509c.get(i3);
                            String str2 = bVar2.f1401a;
                            hashMap.put(str2.substring(1, str2.length() - 1), bVar3.f1401a);
                        }
                    }
                    return hashMap;
                }
            }
        }
        return Collections.emptyMap();
    }

    /* renamed from: b */
    public abstract InterfaceC1449c mo504b(InterfaceC1457c interfaceC1457c, InterfaceC1458d interfaceC1458d);

    @Override // p005b.p113c0.p114a.p116h.p120j.InterfaceC1440d
    @Nullable
    /* renamed from: c */
    public C1436a mo505c() {
        return null;
    }

    @Override // p005b.p113c0.p114a.p116h.InterfaceC1428d
    /* renamed from: d */
    public long mo493d(@NonNull InterfaceC1457c interfaceC1457c) {
        Object obj = this.f1390e;
        if (obj instanceof InterfaceC1428d) {
            return ((InterfaceC1428d) obj).mo493d(interfaceC1457c);
        }
        return -1L;
    }

    @Override // p005b.p113c0.p114a.p116h.InterfaceC1425a
    /* renamed from: e */
    public String mo490e(@NonNull InterfaceC1457c interfaceC1457c) {
        Object obj = this.f1390e;
        if (obj instanceof InterfaceC1425a) {
            return ((InterfaceC1425a) obj).mo490e(interfaceC1457c);
        }
        return null;
    }

    @Override // p005b.p113c0.p114a.p116h.p120j.InterfaceC1442f
    /* renamed from: f */
    public InterfaceC1449c mo506f(@NonNull InterfaceC1457c interfaceC1457c, @NonNull InterfaceC1458d interfaceC1458d) {
        TextUtils.isEmpty(interfaceC1457c.mo528j("Origin"));
        return mo504b(interfaceC1457c, interfaceC1458d);
    }
}

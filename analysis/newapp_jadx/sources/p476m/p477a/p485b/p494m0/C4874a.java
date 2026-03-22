package p476m.p477a.p485b.p494m0;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* renamed from: m.a.b.m0.a */
/* loaded from: classes3.dex */
public class C4874a implements InterfaceC4877d {

    /* renamed from: a */
    public final Map<String, Object> f12476a = new ConcurrentHashMap();

    @Override // p476m.p477a.p485b.p494m0.InterfaceC4877d
    /* renamed from: a */
    public Object mo5545a(String str) {
        C2354n.m2470e1(str, "Id");
        return this.f12476a.get(str);
    }

    @Override // p476m.p477a.p485b.p494m0.InterfaceC4877d
    /* renamed from: b */
    public void mo5546b(String str, Object obj) {
        C2354n.m2470e1(str, "Id");
        if (obj != null) {
            this.f12476a.put(str, obj);
        } else {
            this.f12476a.remove(str);
        }
    }

    public String toString() {
        return this.f12476a.toString();
    }
}

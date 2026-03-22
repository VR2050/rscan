package p476m.p477a.p478a.p479a.p481m;

import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import p476m.p477a.p478a.p479a.InterfaceC4766b;

/* renamed from: m.a.a.a.m.b */
/* loaded from: classes3.dex */
public class C4779b implements InterfaceC4766b, Serializable {
    private static final long serialVersionUID = -4455695752627032559L;

    /* renamed from: c */
    public final Map<String, List<String>> f12249c = new LinkedHashMap();

    /* renamed from: a */
    public String m5459a(String str) {
        List<String> list = this.f12249c.get(str.toLowerCase(Locale.ENGLISH));
        if (list == null) {
            return null;
        }
        return list.get(0);
    }
}

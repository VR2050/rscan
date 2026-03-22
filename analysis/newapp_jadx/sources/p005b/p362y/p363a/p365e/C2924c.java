package p005b.p362y.p363a.p365e;

import com.shuyu.gsyvideoplayer.utils.Debuger;
import java.util.HashMap;
import java.util.Map;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p172h.p173a.p175s.InterfaceC1837b;

/* renamed from: b.y.a.e.c */
/* loaded from: classes2.dex */
public class C2924c implements InterfaceC1837b {

    /* renamed from: a */
    public static final Map<String, String> f8030a = new HashMap();

    @Override // p005b.p172h.p173a.p175s.InterfaceC1837b
    /* renamed from: a */
    public Map<String, String> mo1190a(String str) {
        StringBuilder m586H = C1499a.m586H("****** proxy addHeaders ****** ");
        Map<String, String> map = f8030a;
        m586H.append(map.size());
        Debuger.printfLog(m586H.toString());
        return map;
    }
}

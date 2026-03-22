package p005b.p085c.p102c.p103a.p104a.p109d;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import org.json.JSONObject;
import p005b.p085c.p102c.p103a.p104a.p110e.p112e.C1408b;
import p005b.p085c.p102c.p103a.p104a.p110e.p112e.InterfaceC1407a;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.c.c.a.a.d.b */
/* loaded from: classes.dex */
public final class C1399b {

    /* renamed from: a */
    public File f1329a;

    /* renamed from: b */
    public InterfaceC1407a f1330b;

    public C1399b(String str, InterfaceC1407a interfaceC1407a) {
        this.f1329a = null;
        this.f1330b = null;
        this.f1329a = new File(str);
        this.f1330b = interfaceC1407a;
    }

    /* renamed from: a */
    public static void m479a(C1399b c1399b) {
        String str;
        synchronized (c1399b) {
            File file = c1399b.f1329a;
            if (file != null && file.exists() && c1399b.f1329a.isDirectory() && c1399b.f1329a.list().length != 0) {
                ArrayList arrayList = new ArrayList();
                for (String str2 : c1399b.f1329a.list()) {
                    arrayList.add(str2);
                }
                Collections.sort(arrayList);
                String str3 = (String) arrayList.get(arrayList.size() - 1);
                int size = arrayList.size();
                if (str3.equals(new SimpleDateFormat("yyyyMMdd").format(Calendar.getInstance().getTime()) + ".log")) {
                    if (arrayList.size() >= 2) {
                        str3 = (String) arrayList.get(arrayList.size() - 2);
                        size--;
                    }
                }
                String m4804f = C4195m.m4804f(c1399b.f1329a.getAbsolutePath(), str3);
                JSONObject jSONObject = new JSONObject();
                try {
                    jSONObject.put("type", "id");
                    jSONObject.put("error", m4804f);
                    str = jSONObject.toString();
                } catch (Exception unused) {
                    str = "";
                }
                if (!((C1408b) c1399b.f1330b).m483b(str)) {
                    size--;
                }
                for (int i2 = 0; i2 < size; i2++) {
                    new File(c1399b.f1329a, (String) arrayList.get(i2)).delete();
                }
            }
        }
    }
}

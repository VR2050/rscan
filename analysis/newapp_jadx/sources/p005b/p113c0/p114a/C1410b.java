package p005b.p113c0.p114a;

import android.content.Context;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import p005b.p113c0.p114a.p128j.InterfaceC1483a;
import p005b.p113c0.p114a.p128j.InterfaceC1484b;

/* renamed from: b.c0.a.b */
/* loaded from: classes2.dex */
public class C1410b {

    /* renamed from: a */
    public static final List<String> f1363a;

    /* renamed from: b */
    public Context f1364b;

    static {
        ArrayList arrayList = new ArrayList();
        f1363a = arrayList;
        arrayList.add("AdapterRegister");
        arrayList.add("ConfigRegister");
        arrayList.add("ConverterRegister");
        arrayList.add("InterceptorRegister");
        arrayList.add("ResolverRegister");
    }

    public C1410b(Context context) {
        this.f1364b = context;
    }

    /* renamed from: a */
    public void m484a(InterfaceC1484b interfaceC1484b, String str) {
        String[] strArr;
        try {
            strArr = this.f1364b.getAssets().list("");
        } catch (IOException e2) {
            e2.printStackTrace();
            strArr = null;
        }
        if (strArr == null || strArr.length == 0) {
            return;
        }
        for (String str2 : strArr) {
            if (str2.endsWith(".andserver")) {
                String substring = str2.substring(0, str2.lastIndexOf(".andserver"));
                Iterator<String> it = f1363a.iterator();
                while (it.hasNext()) {
                    try {
                        Class<?> cls = Class.forName(String.format("%s%s%s", substring, ".andserver.processor.generator.", it.next()));
                        if (InterfaceC1483a.class.isAssignableFrom(cls)) {
                            ((InterfaceC1483a) cls.newInstance()).onRegister(this.f1364b, str, interfaceC1484b);
                        }
                    } catch (ClassNotFoundException unused) {
                    }
                }
            }
        }
    }
}

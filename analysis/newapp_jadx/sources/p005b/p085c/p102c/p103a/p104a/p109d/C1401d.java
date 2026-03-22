package p005b.p085c.p102c.p103a.p104a.p109d;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.c.c.a.a.d.d */
/* loaded from: classes.dex */
public final class C1401d {

    /* renamed from: a */
    public static String f1332a = "";

    /* renamed from: b */
    public static String f1333b = "";

    /* renamed from: c */
    public static String f1334c = "";

    /* renamed from: a */
    public static synchronized void m480a(Throwable th) {
        String str;
        synchronized (C1401d.class) {
            ArrayList arrayList = new ArrayList();
            if (th != null) {
                StringWriter stringWriter = new StringWriter();
                th.printStackTrace(new PrintWriter(stringWriter));
                str = stringWriter.toString();
            } else {
                str = "";
            }
            arrayList.add(str);
            m481b(arrayList);
        }
    }

    /* renamed from: b */
    public static synchronized void m481b(List<String> list) {
        synchronized (C1401d.class) {
            if (!C4195m.m4822o(f1333b) && !C4195m.m4822o(f1334c)) {
                StringBuffer stringBuffer = new StringBuffer();
                stringBuffer.append(f1334c);
                Iterator<String> it = list.iterator();
                while (it.hasNext()) {
                    stringBuffer.append(", " + it.next());
                }
                stringBuffer.append("\n");
                try {
                    File file = new File(f1332a);
                    if (!file.exists()) {
                        file.mkdirs();
                    }
                    File file2 = new File(f1332a, f1333b);
                    if (!file2.exists()) {
                        file2.createNewFile();
                    }
                    FileWriter fileWriter = ((long) stringBuffer.length()) + file2.length() <= 51200 ? new FileWriter(file2, true) : new FileWriter(file2);
                    fileWriter.write(stringBuffer.toString());
                    fileWriter.flush();
                    fileWriter.close();
                } catch (Exception unused) {
                }
            }
        }
    }
}

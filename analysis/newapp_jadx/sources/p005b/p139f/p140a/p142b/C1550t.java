package p005b.p139f.p140a.p142b;

import android.app.Activity;
import android.app.ActivityManager;
import android.app.Application;
import android.content.Intent;
import android.os.Handler;
import android.os.Looper;
import android.os.Process;
import android.text.TextUtils;
import androidx.appcompat.widget.ActivityChooserModel;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import p005b.p199l.p258c.C2480j;
import p005b.p199l.p258c.EnumC2419c;
import p005b.p199l.p258c.EnumC2494x;
import p005b.p199l.p258c.p260c0.C2457o;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.f.a.b.t */
/* loaded from: classes.dex */
public class C1550t {

    /* renamed from: b.f.a.b.t$a */
    public static final class a {

        /* renamed from: a */
        public String f1805a;

        /* renamed from: b */
        public LinkedHashMap<String, String> f1806b = new LinkedHashMap<>();

        /* renamed from: c */
        public LinkedHashMap<String, String> f1807c = new LinkedHashMap<>();

        public a(String str) {
            this.f1805a = str;
        }

        /* renamed from: a */
        public String m732a() {
            StringBuilder sb = new StringBuilder();
            for (Map.Entry<String, String> entry : this.f1807c.entrySet()) {
                sb.append(entry.getKey());
                sb.append(": ");
                sb.append(entry.getValue());
                sb.append("\n");
            }
            return sb.toString();
        }

        /* JADX WARN: Can't wrap try/catch for region: R(9:8|(2:9|10)|(6:12|13|14|(1:16)|18|(3:20|(1:22)(1:24)|23)(2:25|(1:27)(2:28|(1:30)(2:31|(1:33)(2:34|(1:36)(2:37|(1:39)(2:40|(1:42)(2:43|(1:45)(2:46|(1:48)(3:49|(1:51)(2:53|(1:55)(2:56|(1:58)(2:59|(1:61)(2:62|(1:64)(2:65|(1:67)(2:68|(1:70)(2:71|(1:73)(2:74|(1:76)(2:77|(1:79)(2:80|(1:82)(1:83)))))))))))|52))))))))))|86|13|14|(0)|18|(0)(0)) */
        /* JADX WARN: Removed duplicated region for block: B:16:0x007c A[Catch: all -> 0x0081, TRY_LEAVE, TryCatch #0 {all -> 0x0081, blocks: (B:14:0x0074, B:16:0x007c), top: B:13:0x0074 }] */
        /* JADX WARN: Removed duplicated region for block: B:20:0x008a  */
        /* JADX WARN: Removed duplicated region for block: B:25:0x00af  */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public java.lang.String toString() {
            /*
                Method dump skipped, instructions count: 721
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: p005b.p139f.p140a.p142b.C1550t.a.toString():java.lang.String");
        }
    }

    /* renamed from: a */
    public static List<Activity> m724a() {
        Object m720c;
        C1549s c1549s = C1549s.f1795c;
        if (!c1549s.f1797f.isEmpty()) {
            return new LinkedList(c1549s.f1797f);
        }
        LinkedList linkedList = new LinkedList();
        Activity activity = null;
        try {
            m720c = c1549s.m720c();
        } catch (Exception e2) {
            e2.getMessage();
        }
        if (m720c != null) {
            Field declaredField = m720c.getClass().getDeclaredField("mActivities");
            declaredField.setAccessible(true);
            Object obj = declaredField.get(m720c);
            if (obj instanceof Map) {
                for (Object obj2 : ((Map) obj).values()) {
                    Class<?> cls = obj2.getClass();
                    Field declaredField2 = cls.getDeclaredField(ActivityChooserModel.ATTRIBUTE_ACTIVITY);
                    declaredField2.setAccessible(true);
                    Activity activity2 = (Activity) declaredField2.get(obj2);
                    if (activity == null) {
                        Field declaredField3 = cls.getDeclaredField("paused");
                        declaredField3.setAccessible(true);
                        if (declaredField3.getBoolean(obj2)) {
                            linkedList.addFirst(activity2);
                        } else {
                            activity = activity2;
                        }
                    } else {
                        linkedList.addFirst(activity2);
                    }
                }
                if (activity != null) {
                    linkedList.addFirst(activity);
                }
            }
        }
        c1549s.f1797f.addAll(linkedList);
        return new LinkedList(c1549s.f1797f);
    }

    public static void addOnAppStatusChangedListener(InterfaceC1546p interfaceC1546p) {
        C1549s.f1795c.addOnAppStatusChangedListener(interfaceC1546p);
    }

    /* renamed from: b */
    public static String m725b() {
        String str;
        String str2;
        List<ActivityManager.RunningAppProcessInfo> runningAppProcesses;
        String str3;
        String str4 = "";
        try {
            BufferedReader bufferedReader = new BufferedReader(new FileReader(new File("/proc/" + Process.myPid() + "/cmdline")));
            str = bufferedReader.readLine().trim();
            bufferedReader.close();
        } catch (Exception e2) {
            e2.printStackTrace();
            str = "";
        }
        if (!TextUtils.isEmpty(str)) {
            return str;
        }
        try {
            ActivityManager activityManager = (ActivityManager) C4195m.m4792Y().getSystemService(ActivityChooserModel.ATTRIBUTE_ACTIVITY);
            if (activityManager != null && (runningAppProcesses = activityManager.getRunningAppProcesses()) != null && runningAppProcesses.size() != 0) {
                int myPid = Process.myPid();
                for (ActivityManager.RunningAppProcessInfo runningAppProcessInfo : runningAppProcesses) {
                    if (runningAppProcessInfo.pid == myPid && (str3 = runningAppProcessInfo.processName) != null) {
                        str2 = str3;
                        break;
                    }
                }
            }
        } catch (Exception unused) {
        }
        str2 = "";
        if (!TextUtils.isEmpty(str2)) {
            return str2;
        }
        try {
            Application m4792Y = C4195m.m4792Y();
            Field field = m4792Y.getClass().getField("mLoadedApk");
            field.setAccessible(true);
            Object obj = field.get(m4792Y);
            Field declaredField = obj.getClass().getDeclaredField("mActivityThread");
            declaredField.setAccessible(true);
            Object obj2 = declaredField.get(obj);
            str4 = (String) obj2.getClass().getDeclaredMethod("getProcessName", new Class[0]).invoke(obj2, new Object[0]);
        } catch (Exception e3) {
            e3.printStackTrace();
        }
        return str4;
    }

    /* renamed from: c */
    public static C2480j m726c() {
        Map<String, C2480j> map = C1534d.f1715a;
        C2480j c2480j = map.get("logUtilsGson");
        if (c2480j != null) {
            return c2480j;
        }
        C2457o c2457o = C2457o.f6598c;
        EnumC2494x enumC2494x = EnumC2494x.f6699c;
        EnumC2419c enumC2419c = EnumC2419c.f6445c;
        HashMap hashMap = new HashMap();
        ArrayList arrayList = new ArrayList();
        ArrayList arrayList2 = new ArrayList();
        ArrayList arrayList3 = new ArrayList(arrayList2.size() + arrayList.size() + 3);
        arrayList3.addAll(arrayList);
        Collections.reverse(arrayList3);
        ArrayList arrayList4 = new ArrayList(arrayList2);
        Collections.reverse(arrayList4);
        arrayList3.addAll(arrayList4);
        C2480j c2480j2 = new C2480j(c2457o, enumC2419c, hashMap, true, false, false, true, true, false, false, enumC2494x, null, 2, 2, arrayList, arrayList2, arrayList3);
        map.put("logUtilsGson", c2480j2);
        return c2480j2;
    }

    /* renamed from: d */
    public static C1539i m727d() {
        boolean z;
        Map<String, C1539i> map = C1539i.f1770a;
        int i2 = 0;
        while (true) {
            if (i2 >= 5) {
                z = true;
                break;
            }
            if (!Character.isWhitespace("Utils".charAt(i2))) {
                z = false;
                break;
            }
            i2++;
        }
        String str = z ? "spUtils" : "Utils";
        Map<String, C1539i> map2 = C1539i.f1770a;
        C1539i c1539i = map2.get(str);
        if (c1539i == null) {
            synchronized (C1539i.class) {
                c1539i = map2.get(str);
                if (c1539i == null) {
                    c1539i = new C1539i(str, 0);
                    map2.put(str, c1539i);
                }
            }
        }
        return c1539i;
    }

    /* renamed from: e */
    public static boolean m728e(Activity activity) {
        return (activity == null || activity.isFinishing() || activity.isDestroyed()) ? false : true;
    }

    /* renamed from: f */
    public static boolean m729f(Intent intent) {
        return C4195m.m4792Y().getPackageManager().queryIntentActivities(intent, 65536).size() > 0;
    }

    /* renamed from: g */
    public static boolean m730g(String str) {
        if (str != null) {
            int length = str.length();
            for (int i2 = 0; i2 < length; i2++) {
                if (!Character.isWhitespace(str.charAt(i2))) {
                    return false;
                }
            }
        }
        return true;
    }

    /* renamed from: h */
    public static void m731h(Runnable runnable) {
        Handler handler = C1540j.f1772a;
        if (Looper.myLooper() == Looper.getMainLooper()) {
            runnable.run();
        } else {
            C1540j.f1772a.post(runnable);
        }
    }

    public static void removeOnAppStatusChangedListener(InterfaceC1546p interfaceC1546p) {
        C1549s.f1795c.removeOnAppStatusChangedListener(interfaceC1546p);
    }
}

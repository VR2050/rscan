package p005b.p139f.p140a.p142b;

import android.os.Environment;
import android.text.TextUtils;
import android.util.Log;
import androidx.collection.SimpleArrayMap;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p139f.p140a.p142b.C1550t;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.f.a.b.e */
/* loaded from: classes.dex */
public final class C1535e {

    /* renamed from: e */
    public static SimpleDateFormat f1720e;

    /* renamed from: a */
    public static final char[] f1716a = {'V', 'D', 'I', 'W', 'E', 'A'};

    /* renamed from: b */
    public static final String f1717b = System.getProperty("file.separator");

    /* renamed from: c */
    public static final String f1718c = System.getProperty("line.separator");

    /* renamed from: d */
    public static final b f1719d = new b(null);

    /* renamed from: f */
    public static final ExecutorService f1721f = Executors.newSingleThreadExecutor();

    /* renamed from: g */
    public static final SimpleArrayMap<Class, c> f1722g = new SimpleArrayMap<>();

    /* renamed from: b.f.a.b.e$a */
    public class a implements Runnable {

        /* renamed from: c */
        public final /* synthetic */ int f1723c;

        /* renamed from: e */
        public final /* synthetic */ d f1724e;

        /* renamed from: f */
        public final /* synthetic */ String f1725f;

        public a(int i2, d dVar, String str) {
            this.f1723c = i2;
            this.f1724e = dVar;
            this.f1725f = str;
        }

        @Override // java.lang.Runnable
        public void run() {
            int i2 = this.f1723c;
            String str = this.f1724e.f1729a;
            String str2 = this.f1724e.f1731c + this.f1725f;
            Date date = new Date();
            if (C1535e.f1720e == null) {
                C1535e.f1720e = new SimpleDateFormat("yyyy_MM_dd HH:mm:ss.SSS ", Locale.getDefault());
            }
            String format = C1535e.f1720e.format(date);
            boolean z = false;
            String substring = format.substring(0, 10);
            if (C1535e.f1720e == null) {
                C1535e.f1720e = new SimpleDateFormat("yyyy_MM_dd HH:mm:ss.SSS ", Locale.getDefault());
            }
            String substring2 = C1535e.f1720e.format(date).substring(0, 10);
            StringBuilder sb = new StringBuilder();
            b bVar = C1535e.f1719d;
            C1499a.m608b0(sb, bVar.f1726a, "util", "_", substring2);
            sb.append("_");
            String str3 = bVar.f1727b;
            String m582D = C1499a.m582D(sb, str3 == null ? "" : str3.replace(":", "_"), ".txt");
            File file = new File(m582D);
            if (file.exists()) {
                z = file.isFile();
            } else if (C1533c.m687a(file.getParentFile())) {
                try {
                    boolean createNewFile = file.createNewFile();
                    if (createNewFile) {
                        C1535e.m693f(m582D, substring);
                    }
                    z = createNewFile;
                } catch (IOException e2) {
                    e2.printStackTrace();
                }
            }
            if (z) {
                StringBuilder m586H = C1499a.m586H(format.substring(11));
                m586H.append(C1535e.f1716a[i2 - 2]);
                m586H.append("/");
                m586H.append(str);
                m586H.append(str2);
                m586H.append(C1535e.f1718c);
                C1535e.m690c(m582D, m586H.toString());
            }
        }
    }

    /* renamed from: b.f.a.b.e$b */
    public static final class b {

        /* renamed from: a */
        public String f1726a;

        /* renamed from: b */
        public String f1727b = C1550t.m725b();

        /* renamed from: c */
        public C1550t.a f1728c = new C1550t.a("Log");

        public b(a aVar) {
            if (!"mounted".equals(Environment.getExternalStorageState()) || C4195m.m4792Y().getExternalFilesDir(null) == null) {
                StringBuilder sb = new StringBuilder();
                sb.append(C4195m.m4792Y().getFilesDir());
                String str = C1535e.f1717b;
                this.f1726a = C1499a.m583E(sb, str, "log", str);
                return;
            }
            StringBuilder sb2 = new StringBuilder();
            sb2.append(C4195m.m4792Y().getExternalFilesDir(null));
            String str2 = C1535e.f1717b;
            this.f1726a = C1499a.m583E(sb2, str2, "log", str2);
        }

        /* renamed from: a */
        public final String m694a() {
            if (C1550t.m730g("")) {
            }
            return "";
        }

        public String toString() {
            StringBuilder m586H = C1499a.m586H("process: ");
            String str = this.f1727b;
            m586H.append(str == null ? "" : str.replace(":", "_"));
            String str2 = C1535e.f1718c;
            m586H.append(str2);
            m586H.append("logSwitch: ");
            m586H.append(true);
            m586H.append(str2);
            m586H.append("consoleSwitch: ");
            m586H.append(true);
            m586H.append(str2);
            m586H.append("tag: ");
            m586H.append(m694a().equals("") ? "null" : m694a());
            m586H.append(str2);
            m586H.append("headSwitch: ");
            m586H.append(true);
            m586H.append(str2);
            m586H.append("fileSwitch: ");
            m586H.append(false);
            m586H.append(str2);
            m586H.append("dir: ");
            C1499a.m608b0(m586H, this.f1726a, str2, "filePrefix: ", "util");
            m586H.append(str2);
            m586H.append("borderSwitch: ");
            m586H.append(true);
            m586H.append(str2);
            m586H.append("singleTagSwitch: ");
            m586H.append(true);
            m586H.append(str2);
            m586H.append("consoleFilter: ");
            char[] cArr = C1535e.f1716a;
            char[] cArr2 = C1535e.f1716a;
            m586H.append(cArr2[0]);
            m586H.append(str2);
            m586H.append("fileFilter: ");
            m586H.append(cArr2[0]);
            m586H.append(str2);
            m586H.append("stackDeep: ");
            m586H.append(1);
            m586H.append(str2);
            m586H.append("stackOffset: ");
            m586H.append(0);
            m586H.append(str2);
            m586H.append("saveDays: ");
            m586H.append(-1);
            m586H.append(str2);
            m586H.append("formatter: ");
            m586H.append(C1535e.f1722g);
            m586H.append(str2);
            m586H.append("fileWriter: ");
            m586H.append((Object) null);
            m586H.append(str2);
            m586H.append("onConsoleOutputListener: ");
            m586H.append((Object) null);
            m586H.append(str2);
            m586H.append("onFileOutputListener: ");
            m586H.append((Object) null);
            m586H.append(str2);
            m586H.append("fileExtraHeader: ");
            m586H.append(this.f1728c.m732a());
            return m586H.toString();
        }
    }

    /* renamed from: b.f.a.b.e$c */
    public static abstract class c<T> {
        /* renamed from: a */
        public abstract String m695a(T t);
    }

    /* renamed from: b.f.a.b.e$d */
    public static final class d {

        /* renamed from: a */
        public String f1729a;

        /* renamed from: b */
        public String[] f1730b;

        /* renamed from: c */
        public String f1731c;

        public d(String str, String[] strArr, String str2) {
            this.f1729a = str;
            this.f1730b = strArr;
            this.f1731c = str2;
        }
    }

    /* renamed from: a */
    public static String m688a(Object obj) {
        String obj2;
        if (obj == null) {
            return "null";
        }
        SimpleArrayMap<Class, c> simpleArrayMap = f1722g;
        if (!simpleArrayMap.isEmpty()) {
            Class<?> cls = obj.getClass();
            if (cls.isAnonymousClass() || cls.isSynthetic()) {
                Type[] genericInterfaces = cls.getGenericInterfaces();
                if (genericInterfaces.length == 1) {
                    Type type = genericInterfaces[0];
                    while (type instanceof ParameterizedType) {
                        type = ((ParameterizedType) type).getRawType();
                    }
                    obj2 = type.toString();
                } else {
                    Type genericSuperclass = cls.getGenericSuperclass();
                    while (genericSuperclass instanceof ParameterizedType) {
                        genericSuperclass = ((ParameterizedType) genericSuperclass).getRawType();
                    }
                    obj2 = genericSuperclass.toString();
                }
                if (obj2.startsWith("class ")) {
                    obj2 = obj2.substring(6);
                } else if (obj2.startsWith("interface ")) {
                    obj2 = obj2.substring(10);
                }
                try {
                    cls = Class.forName(obj2);
                } catch (ClassNotFoundException e2) {
                    e2.printStackTrace();
                }
            }
            c cVar = simpleArrayMap.get(cls);
            if (cVar != null) {
                return cVar.m695a(obj);
            }
        }
        return C4195m.m4843y0(obj, -1);
    }

    /* renamed from: b */
    public static String m689b(StackTraceElement stackTraceElement) {
        String fileName = stackTraceElement.getFileName();
        if (fileName != null) {
            return fileName;
        }
        String className = stackTraceElement.getClassName();
        String[] split = className.split("\\.");
        if (split.length > 0) {
            className = split[split.length - 1];
        }
        int indexOf = className.indexOf(36);
        if (indexOf != -1) {
            className = className.substring(0, indexOf);
        }
        return C1499a.m637w(className, ".java");
    }

    /* renamed from: c */
    public static void m690c(String str, String str2) {
        boolean createNewFile;
        Throwable th;
        BufferedWriter bufferedWriter;
        IOException e2;
        Objects.requireNonNull(f1719d);
        int i2 = C1533c.f1714a;
        BufferedWriter bufferedWriter2 = null;
        File file = C1550t.m730g(str) ? null : new File(str);
        if (file != null && str2 != null) {
            if (file.exists()) {
                createNewFile = file.isFile();
            } else {
                if (C1533c.m687a(file.getParentFile())) {
                    try {
                        createNewFile = file.createNewFile();
                    } catch (IOException e3) {
                        e3.printStackTrace();
                    }
                }
                createNewFile = false;
            }
            try {
                try {
                } catch (IOException e4) {
                    e4.printStackTrace();
                }
                if (createNewFile) {
                    try {
                        bufferedWriter = new BufferedWriter(new FileWriter(file, true));
                    } catch (IOException e5) {
                        e2 = e5;
                    }
                    try {
                        bufferedWriter.write(str2);
                        bufferedWriter.close();
                    } catch (IOException e6) {
                        e2 = e6;
                        bufferedWriter2 = bufferedWriter;
                        e2.printStackTrace();
                        if (bufferedWriter2 != null) {
                            bufferedWriter2.close();
                        }
                        Objects.requireNonNull(f1719d);
                    } catch (Throwable th2) {
                        th = th2;
                        if (bufferedWriter != null) {
                            try {
                                bufferedWriter.close();
                            } catch (IOException e7) {
                                e7.printStackTrace();
                            }
                        }
                        throw th;
                    }
                } else {
                    String str3 = "create file <" + file + "> failed.";
                }
            } catch (Throwable th3) {
                th = th3;
                bufferedWriter = bufferedWriter2;
            }
        }
        Objects.requireNonNull(f1719d);
    }

    /* JADX WARN: Removed duplicated region for block: B:24:0x0109  */
    /* renamed from: d */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void m691d(int r16, java.lang.String r17, java.lang.Object... r18) {
        /*
            Method dump skipped, instructions count: 524
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p139f.p140a.p142b.C1535e.m691d(int, java.lang.String, java.lang.Object[]):void");
    }

    /* renamed from: e */
    public static void m692e(int i2, String str, String str2) {
        Log.println(i2, str, str2);
        Objects.requireNonNull(f1719d);
    }

    /* renamed from: f */
    public static void m693f(String str, String str2) {
        b bVar = f1719d;
        LinkedHashMap<String, String> linkedHashMap = bVar.f1728c.f1806b;
        if (!TextUtils.isEmpty("Date of Log") && !TextUtils.isEmpty(str2)) {
            linkedHashMap.put("Date of Log        ", str2);
        }
        m690c(str, bVar.f1728c.toString());
    }
}

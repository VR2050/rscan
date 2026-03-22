package p005b.p143g.p144a.p145k;

import android.annotation.TargetApi;
import android.os.Build;
import android.os.StrictMode;
import java.io.BufferedWriter;
import java.io.Closeable;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.concurrent.Callable;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import p005b.p131d.p132a.p133a.C1499a;
import p458k.p459p0.p460d.C4406e;

/* renamed from: b.g.a.k.a */
/* loaded from: classes.dex */
public final class C1561a implements Closeable {

    /* renamed from: c */
    public final File f1887c;

    /* renamed from: e */
    public final File f1888e;

    /* renamed from: f */
    public final File f1889f;

    /* renamed from: g */
    public final File f1890g;

    /* renamed from: h */
    public final int f1891h;

    /* renamed from: i */
    public long f1892i;

    /* renamed from: j */
    public final int f1893j;

    /* renamed from: l */
    public Writer f1895l;

    /* renamed from: n */
    public int f1897n;

    /* renamed from: k */
    public long f1894k = 0;

    /* renamed from: m */
    public final LinkedHashMap<String, d> f1896m = new LinkedHashMap<>(0, 0.75f, true);

    /* renamed from: o */
    public long f1898o = 0;

    /* renamed from: p */
    public final ThreadPoolExecutor f1899p = new ThreadPoolExecutor(0, 1, 60, TimeUnit.SECONDS, new LinkedBlockingQueue(), new b(null));

    /* renamed from: q */
    public final Callable<Void> f1900q = new a();

    /* renamed from: b.g.a.k.a$a */
    public class a implements Callable<Void> {
        public a() {
        }

        @Override // java.util.concurrent.Callable
        public Void call() {
            synchronized (C1561a.this) {
                C1561a c1561a = C1561a.this;
                if (c1561a.f1895l == null) {
                    return null;
                }
                c1561a.m792S();
                if (C1561a.this.m796t()) {
                    C1561a.this.m791I();
                    C1561a.this.f1897n = 0;
                }
                return null;
            }
        }
    }

    /* renamed from: b.g.a.k.a$b */
    public static final class b implements ThreadFactory {
        public b(a aVar) {
        }

        @Override // java.util.concurrent.ThreadFactory
        public synchronized Thread newThread(Runnable runnable) {
            Thread thread;
            thread = new Thread(runnable, "glide-disk-lru-cache-thread");
            thread.setPriority(1);
            return thread;
        }
    }

    /* renamed from: b.g.a.k.a$c */
    public final class c {

        /* renamed from: a */
        public final d f1902a;

        /* renamed from: b */
        public final boolean[] f1903b;

        /* renamed from: c */
        public boolean f1904c;

        public c(d dVar, a aVar) {
            this.f1902a = dVar;
            this.f1903b = dVar.f1910e ? null : new boolean[C1561a.this.f1893j];
        }

        /* renamed from: a */
        public void m797a() {
            C1561a.m783b(C1561a.this, this, false);
        }

        /* renamed from: b */
        public File m798b(int i2) {
            File file;
            synchronized (C1561a.this) {
                d dVar = this.f1902a;
                if (dVar.f1911f != this) {
                    throw new IllegalStateException();
                }
                if (!dVar.f1910e) {
                    this.f1903b[i2] = true;
                }
                file = dVar.f1909d[i2];
                if (!C1561a.this.f1887c.exists()) {
                    C1561a.this.f1887c.mkdirs();
                }
            }
            return file;
        }
    }

    /* renamed from: b.g.a.k.a$d */
    public final class d {

        /* renamed from: a */
        public final String f1906a;

        /* renamed from: b */
        public final long[] f1907b;

        /* renamed from: c */
        public File[] f1908c;

        /* renamed from: d */
        public File[] f1909d;

        /* renamed from: e */
        public boolean f1910e;

        /* renamed from: f */
        public c f1911f;

        /* renamed from: g */
        public long f1912g;

        public d(String str, a aVar) {
            this.f1906a = str;
            int i2 = C1561a.this.f1893j;
            this.f1907b = new long[i2];
            this.f1908c = new File[i2];
            this.f1909d = new File[i2];
            StringBuilder sb = new StringBuilder(str);
            sb.append('.');
            int length = sb.length();
            for (int i3 = 0; i3 < C1561a.this.f1893j; i3++) {
                sb.append(i3);
                this.f1908c[i3] = new File(C1561a.this.f1887c, sb.toString());
                sb.append(".tmp");
                this.f1909d[i3] = new File(C1561a.this.f1887c, sb.toString());
                sb.setLength(length);
            }
        }

        /* renamed from: a */
        public String m799a() {
            StringBuilder sb = new StringBuilder();
            for (long j2 : this.f1907b) {
                sb.append(' ');
                sb.append(j2);
            }
            return sb.toString();
        }

        /* renamed from: b */
        public final IOException m800b(String[] strArr) {
            StringBuilder m586H = C1499a.m586H("unexpected journal line: ");
            m586H.append(Arrays.toString(strArr));
            throw new IOException(m586H.toString());
        }
    }

    /* renamed from: b.g.a.k.a$e */
    public final class e {

        /* renamed from: a */
        public final File[] f1914a;

        public e(C1561a c1561a, String str, long j2, File[] fileArr, long[] jArr, a aVar) {
            this.f1914a = fileArr;
        }
    }

    public C1561a(File file, int i2, int i3, long j2) {
        this.f1887c = file;
        this.f1891h = i2;
        this.f1888e = new File(file, "journal");
        this.f1889f = new File(file, "journal.tmp");
        this.f1890g = new File(file, "journal.bkp");
        this.f1893j = i3;
        this.f1892i = j2;
    }

    /* renamed from: P */
    public static void m782P(File file, File file2, boolean z) {
        if (z) {
            m785k(file2);
        }
        if (!file.renameTo(file2)) {
            throw new IOException();
        }
    }

    /* renamed from: b */
    public static void m783b(C1561a c1561a, c cVar, boolean z) {
        synchronized (c1561a) {
            d dVar = cVar.f1902a;
            if (dVar.f1911f != cVar) {
                throw new IllegalStateException();
            }
            if (z && !dVar.f1910e) {
                for (int i2 = 0; i2 < c1561a.f1893j; i2++) {
                    if (!cVar.f1903b[i2]) {
                        cVar.m797a();
                        throw new IllegalStateException("Newly created entry didn't create value for index " + i2);
                    }
                    if (!dVar.f1909d[i2].exists()) {
                        cVar.m797a();
                        return;
                    }
                }
            }
            for (int i3 = 0; i3 < c1561a.f1893j; i3++) {
                File file = dVar.f1909d[i3];
                if (!z) {
                    m785k(file);
                } else if (file.exists()) {
                    File file2 = dVar.f1908c[i3];
                    file.renameTo(file2);
                    long j2 = dVar.f1907b[i3];
                    long length = file2.length();
                    dVar.f1907b[i3] = length;
                    c1561a.f1894k = (c1561a.f1894k - j2) + length;
                }
            }
            c1561a.f1897n++;
            dVar.f1911f = null;
            if (dVar.f1910e || z) {
                dVar.f1910e = true;
                c1561a.f1895l.append((CharSequence) C4406e.f11571e);
                c1561a.f1895l.append(' ');
                c1561a.f1895l.append((CharSequence) dVar.f1906a);
                c1561a.f1895l.append((CharSequence) dVar.m799a());
                c1561a.f1895l.append('\n');
                if (z) {
                    long j3 = c1561a.f1898o;
                    c1561a.f1898o = 1 + j3;
                    dVar.f1912g = j3;
                }
            } else {
                c1561a.f1896m.remove(dVar.f1906a);
                c1561a.f1895l.append((CharSequence) C4406e.f11573g);
                c1561a.f1895l.append(' ');
                c1561a.f1895l.append((CharSequence) dVar.f1906a);
                c1561a.f1895l.append('\n');
            }
            m786q(c1561a.f1895l);
            if (c1561a.f1894k > c1561a.f1892i || c1561a.m796t()) {
                c1561a.f1899p.submit(c1561a.f1900q);
            }
        }
    }

    @TargetApi(26)
    /* renamed from: e */
    public static void m784e(Writer writer) {
        if (Build.VERSION.SDK_INT < 26) {
            writer.close();
            return;
        }
        StrictMode.ThreadPolicy threadPolicy = StrictMode.getThreadPolicy();
        StrictMode.setThreadPolicy(new StrictMode.ThreadPolicy.Builder(threadPolicy).permitUnbufferedIo().build());
        try {
            writer.close();
        } finally {
            StrictMode.setThreadPolicy(threadPolicy);
        }
    }

    /* renamed from: k */
    public static void m785k(File file) {
        if (file.exists() && !file.delete()) {
            throw new IOException();
        }
    }

    @TargetApi(26)
    /* renamed from: q */
    public static void m786q(Writer writer) {
        if (Build.VERSION.SDK_INT < 26) {
            writer.flush();
            return;
        }
        StrictMode.ThreadPolicy threadPolicy = StrictMode.getThreadPolicy();
        StrictMode.setThreadPolicy(new StrictMode.ThreadPolicy.Builder(threadPolicy).permitUnbufferedIo().build());
        try {
            writer.flush();
        } finally {
            StrictMode.setThreadPolicy(threadPolicy);
        }
    }

    /* renamed from: v */
    public static C1561a m787v(File file, int i2, int i3, long j2) {
        if (j2 <= 0) {
            throw new IllegalArgumentException("maxSize <= 0");
        }
        if (i3 <= 0) {
            throw new IllegalArgumentException("valueCount <= 0");
        }
        File file2 = new File(file, "journal.bkp");
        if (file2.exists()) {
            File file3 = new File(file, "journal");
            if (file3.exists()) {
                file2.delete();
            } else {
                m782P(file2, file3, false);
            }
        }
        C1561a c1561a = new C1561a(file, i2, i3, j2);
        if (c1561a.f1888e.exists()) {
            try {
                c1561a.m789D();
                c1561a.m788C();
                return c1561a;
            } catch (IOException e2) {
                System.out.println("DiskLruCache " + file + " is corrupt: " + e2.getMessage() + ", removing");
                c1561a.close();
                C1563c.m803a(c1561a.f1887c);
            }
        }
        file.mkdirs();
        C1561a c1561a2 = new C1561a(file, i2, i3, j2);
        c1561a2.m791I();
        return c1561a2;
    }

    /* renamed from: C */
    public final void m788C() {
        m785k(this.f1889f);
        Iterator<d> it = this.f1896m.values().iterator();
        while (it.hasNext()) {
            d next = it.next();
            int i2 = 0;
            if (next.f1911f == null) {
                while (i2 < this.f1893j) {
                    this.f1894k += next.f1907b[i2];
                    i2++;
                }
            } else {
                next.f1911f = null;
                while (i2 < this.f1893j) {
                    m785k(next.f1908c[i2]);
                    m785k(next.f1909d[i2]);
                    i2++;
                }
                it.remove();
            }
        }
    }

    /* renamed from: D */
    public final void m789D() {
        C1562b c1562b = new C1562b(new FileInputStream(this.f1888e), C1563c.f1921a);
        try {
            String m802d = c1562b.m802d();
            String m802d2 = c1562b.m802d();
            String m802d3 = c1562b.m802d();
            String m802d4 = c1562b.m802d();
            String m802d5 = c1562b.m802d();
            if (!"libcore.io.DiskLruCache".equals(m802d) || !"1".equals(m802d2) || !Integer.toString(this.f1891h).equals(m802d3) || !Integer.toString(this.f1893j).equals(m802d4) || !"".equals(m802d5)) {
                throw new IOException("unexpected journal header: [" + m802d + ", " + m802d2 + ", " + m802d4 + ", " + m802d5 + "]");
            }
            int i2 = 0;
            while (true) {
                try {
                    m790E(c1562b.m802d());
                    i2++;
                } catch (EOFException unused) {
                    this.f1897n = i2 - this.f1896m.size();
                    if (c1562b.f1919h == -1) {
                        m791I();
                    } else {
                        this.f1895l = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(this.f1888e, true), C1563c.f1921a));
                    }
                    try {
                        c1562b.close();
                        return;
                    } catch (RuntimeException e2) {
                        throw e2;
                    } catch (Exception unused2) {
                        return;
                    }
                }
            }
        } catch (Throwable th) {
            try {
                c1562b.close();
            } catch (RuntimeException e3) {
                throw e3;
            } catch (Exception unused3) {
            }
            throw th;
        }
    }

    /* renamed from: E */
    public final void m790E(String str) {
        String substring;
        int indexOf = str.indexOf(32);
        if (indexOf == -1) {
            throw new IOException(C1499a.m637w("unexpected journal line: ", str));
        }
        int i2 = indexOf + 1;
        int indexOf2 = str.indexOf(32, i2);
        if (indexOf2 == -1) {
            substring = str.substring(i2);
            if (indexOf == 6 && str.startsWith(C4406e.f11573g)) {
                this.f1896m.remove(substring);
                return;
            }
        } else {
            substring = str.substring(i2, indexOf2);
        }
        d dVar = this.f1896m.get(substring);
        if (dVar == null) {
            dVar = new d(substring, null);
            this.f1896m.put(substring, dVar);
        }
        if (indexOf2 == -1 || indexOf != 5 || !str.startsWith(C4406e.f11571e)) {
            if (indexOf2 == -1 && indexOf == 5 && str.startsWith(C4406e.f11572f)) {
                dVar.f1911f = new c(dVar, null);
                return;
            } else {
                if (indexOf2 != -1 || indexOf != 4 || !str.startsWith(C4406e.f11574h)) {
                    throw new IOException(C1499a.m637w("unexpected journal line: ", str));
                }
                return;
            }
        }
        String[] split = str.substring(indexOf2 + 1).split(" ");
        dVar.f1910e = true;
        dVar.f1911f = null;
        if (split.length != C1561a.this.f1893j) {
            dVar.m800b(split);
            throw null;
        }
        for (int i3 = 0; i3 < split.length; i3++) {
            try {
                dVar.f1907b[i3] = Long.parseLong(split[i3]);
            } catch (NumberFormatException unused) {
                dVar.m800b(split);
                throw null;
            }
        }
    }

    /* renamed from: I */
    public final synchronized void m791I() {
        Writer writer = this.f1895l;
        if (writer != null) {
            m784e(writer);
        }
        BufferedWriter bufferedWriter = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(this.f1889f), C1563c.f1921a));
        try {
            bufferedWriter.write("libcore.io.DiskLruCache");
            bufferedWriter.write("\n");
            bufferedWriter.write("1");
            bufferedWriter.write("\n");
            bufferedWriter.write(Integer.toString(this.f1891h));
            bufferedWriter.write("\n");
            bufferedWriter.write(Integer.toString(this.f1893j));
            bufferedWriter.write("\n");
            bufferedWriter.write("\n");
            for (d dVar : this.f1896m.values()) {
                if (dVar.f1911f != null) {
                    bufferedWriter.write("DIRTY " + dVar.f1906a + '\n');
                } else {
                    bufferedWriter.write("CLEAN " + dVar.f1906a + dVar.m799a() + '\n');
                }
            }
            m784e(bufferedWriter);
            if (this.f1888e.exists()) {
                m782P(this.f1888e, this.f1890g, true);
            }
            m782P(this.f1889f, this.f1888e, false);
            this.f1890g.delete();
            this.f1895l = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(this.f1888e, true), C1563c.f1921a));
        } catch (Throwable th) {
            m784e(bufferedWriter);
            throw th;
        }
    }

    /* renamed from: S */
    public final void m792S() {
        while (this.f1894k > this.f1892i) {
            String key = this.f1896m.entrySet().iterator().next().getKey();
            synchronized (this) {
                m793d();
                d dVar = this.f1896m.get(key);
                if (dVar != null && dVar.f1911f == null) {
                    for (int i2 = 0; i2 < this.f1893j; i2++) {
                        File file = dVar.f1908c[i2];
                        if (file.exists() && !file.delete()) {
                            throw new IOException("failed to delete " + file);
                        }
                        long j2 = this.f1894k;
                        long[] jArr = dVar.f1907b;
                        this.f1894k = j2 - jArr[i2];
                        jArr[i2] = 0;
                    }
                    this.f1897n++;
                    this.f1895l.append((CharSequence) C4406e.f11573g);
                    this.f1895l.append(' ');
                    this.f1895l.append((CharSequence) key);
                    this.f1895l.append('\n');
                    this.f1896m.remove(key);
                    if (m796t()) {
                        this.f1899p.submit(this.f1900q);
                    }
                }
            }
        }
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public synchronized void close() {
        if (this.f1895l == null) {
            return;
        }
        Iterator it = new ArrayList(this.f1896m.values()).iterator();
        while (it.hasNext()) {
            c cVar = ((d) it.next()).f1911f;
            if (cVar != null) {
                cVar.m797a();
            }
        }
        m792S();
        m784e(this.f1895l);
        this.f1895l = null;
    }

    /* renamed from: d */
    public final void m793d() {
        if (this.f1895l == null) {
            throw new IllegalStateException("cache is closed");
        }
    }

    /* renamed from: o */
    public c m794o(String str) {
        synchronized (this) {
            m793d();
            d dVar = this.f1896m.get(str);
            if (dVar == null) {
                dVar = new d(str, null);
                this.f1896m.put(str, dVar);
            } else if (dVar.f1911f != null) {
                return null;
            }
            c cVar = new c(dVar, null);
            dVar.f1911f = cVar;
            this.f1895l.append((CharSequence) C4406e.f11572f);
            this.f1895l.append(' ');
            this.f1895l.append((CharSequence) str);
            this.f1895l.append('\n');
            m786q(this.f1895l);
            return cVar;
        }
    }

    /* renamed from: s */
    public synchronized e m795s(String str) {
        m793d();
        d dVar = this.f1896m.get(str);
        if (dVar == null) {
            return null;
        }
        if (!dVar.f1910e) {
            return null;
        }
        for (File file : dVar.f1908c) {
            if (!file.exists()) {
                return null;
            }
        }
        this.f1897n++;
        this.f1895l.append((CharSequence) C4406e.f11574h);
        this.f1895l.append(' ');
        this.f1895l.append((CharSequence) str);
        this.f1895l.append('\n');
        if (m796t()) {
            this.f1899p.submit(this.f1900q);
        }
        return new e(this, str, dVar.f1912g, dVar.f1908c, dVar.f1907b, null);
    }

    /* renamed from: t */
    public final boolean m796t() {
        int i2 = this.f1897n;
        return i2 >= 2000 && i2 >= this.f1896m.size();
    }
}

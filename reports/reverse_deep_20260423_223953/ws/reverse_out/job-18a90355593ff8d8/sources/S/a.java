package S;

import R.a;
import S.f;
import W.c;
import android.os.Environment;
import e0.C0514d;
import e0.InterfaceC0511a;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

/* JADX INFO: loaded from: classes.dex */
public class a implements S.f {

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static final Class f2640f = a.class;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    static final long f2641g = TimeUnit.MINUTES.toMillis(30);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final File f2642a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final boolean f2643b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final File f2644c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final R.a f2645d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final InterfaceC0511a f2646e;

    /* JADX INFO: renamed from: S.a$a, reason: collision with other inner class name */
    private class C0039a implements W.b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final List f2647a;

        @Override // W.b
        public void c(File file) {
            c cVarW = a.this.w(file);
            if (cVarW == null || cVarW.f2653a != ".cnt") {
                return;
            }
            this.f2647a.add(new b(cVarW.f2654b, file));
        }

        public List d() {
            return Collections.unmodifiableList(this.f2647a);
        }

        private C0039a() {
            this.f2647a = new ArrayList();
        }

        @Override // W.b
        public void a(File file) {
        }

        @Override // W.b
        public void b(File file) {
        }
    }

    static class b implements f.a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final String f2649a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final Q.b f2650b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private long f2651c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private long f2652d;

        @Override // S.f.a
        public long a() {
            if (this.f2652d < 0) {
                this.f2652d = this.f2650b.d().lastModified();
            }
            return this.f2652d;
        }

        public Q.b b() {
            return this.f2650b;
        }

        @Override // S.f.a
        public String getId() {
            return this.f2649a;
        }

        @Override // S.f.a
        public long i() {
            if (this.f2651c < 0) {
                this.f2651c = this.f2650b.size();
            }
            return this.f2651c;
        }

        private b(String str, File file) {
            X.k.g(file);
            this.f2649a = (String) X.k.g(str);
            this.f2650b = Q.b.b(file);
            this.f2651c = -1L;
            this.f2652d = -1L;
        }
    }

    private static class c {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public final String f2653a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        public final String f2654b;

        public static c b(File file) {
            String strU;
            String name = file.getName();
            int iLastIndexOf = name.lastIndexOf(46);
            if (iLastIndexOf <= 0 || (strU = a.u(name.substring(iLastIndexOf))) == null) {
                return null;
            }
            String strSubstring = name.substring(0, iLastIndexOf);
            if (strU.equals(".tmp")) {
                int iLastIndexOf2 = strSubstring.lastIndexOf(46);
                if (iLastIndexOf2 <= 0) {
                    return null;
                }
                strSubstring = strSubstring.substring(0, iLastIndexOf2);
            }
            return new c(strU, strSubstring);
        }

        public File a(File file) {
            return File.createTempFile(this.f2654b + ".", ".tmp", file);
        }

        public String c(String str) {
            return str + File.separator + this.f2654b + this.f2653a;
        }

        public String toString() {
            return this.f2653a + "(" + this.f2654b + ")";
        }

        private c(String str, String str2) {
            this.f2653a = str;
            this.f2654b = str2;
        }
    }

    private static class d extends IOException {
        public d(long j3, long j4) {
            super("File was not written completely. Expected: " + j3 + ", found: " + j4);
        }
    }

    class e implements f.b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final String f2655a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final File f2656b;

        public e(String str, File file) {
            this.f2655a = str;
            this.f2656b = file;
        }

        @Override // S.f.b
        public boolean a() {
            return !this.f2656b.exists() || this.f2656b.delete();
        }

        @Override // S.f.b
        public void b(R.j jVar, Object obj) throws IOException {
            try {
                FileOutputStream fileOutputStream = new FileOutputStream(this.f2656b);
                try {
                    X.c cVar = new X.c(fileOutputStream);
                    jVar.a(cVar);
                    cVar.flush();
                    long jB = cVar.b();
                    fileOutputStream.close();
                    if (this.f2656b.length() != jB) {
                        throw new d(jB, this.f2656b.length());
                    }
                } catch (Throwable th) {
                    fileOutputStream.close();
                    throw th;
                }
            } catch (FileNotFoundException e3) {
                a.this.f2645d.a(a.EnumC0038a.WRITE_UPDATE_FILE_NOT_FOUND, a.f2640f, "updateResource", e3);
                throw e3;
            }
        }

        @Override // S.f.b
        public Q.a c(Object obj) {
            return d(obj, a.this.f2646e.now());
        }

        public Q.a d(Object obj, long j3) throws c.d {
            File fileS = a.this.s(this.f2655a);
            try {
                W.c.b(this.f2656b, fileS);
                if (fileS.exists()) {
                    fileS.setLastModified(j3);
                }
                return Q.b.b(fileS);
            } catch (c.d e3) {
                Throwable cause = e3.getCause();
                a.this.f2645d.a(cause != null ? !(cause instanceof c.C0044c) ? cause instanceof FileNotFoundException ? a.EnumC0038a.WRITE_RENAME_FILE_TEMPFILE_NOT_FOUND : a.EnumC0038a.WRITE_RENAME_FILE_OTHER : a.EnumC0038a.WRITE_RENAME_FILE_TEMPFILE_PARENT_NOT_FOUND : a.EnumC0038a.WRITE_RENAME_FILE_OTHER, a.f2640f, "commit", e3);
                throw e3;
            }
        }
    }

    private class f implements W.b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private boolean f2658a;

        private boolean d(File file) {
            c cVarW = a.this.w(file);
            if (cVarW == null) {
                return false;
            }
            String str = cVarW.f2653a;
            if (str == ".tmp") {
                return e(file);
            }
            X.k.i(str == ".cnt");
            return true;
        }

        private boolean e(File file) {
            return file.lastModified() > a.this.f2646e.now() - a.f2641g;
        }

        @Override // W.b
        public void a(File file) {
            if (this.f2658a || !file.equals(a.this.f2644c)) {
                return;
            }
            this.f2658a = true;
        }

        @Override // W.b
        public void b(File file) {
            if (!a.this.f2642a.equals(file) && !this.f2658a) {
                file.delete();
            }
            if (this.f2658a && file.equals(a.this.f2644c)) {
                this.f2658a = false;
            }
        }

        @Override // W.b
        public void c(File file) {
            if (this.f2658a && d(file)) {
                return;
            }
            file.delete();
        }

        private f() {
        }
    }

    public a(File file, int i3, R.a aVar) {
        X.k.g(file);
        this.f2642a = file;
        this.f2643b = A(file, aVar);
        this.f2644c = new File(file, z(i3));
        this.f2645d = aVar;
        D();
        this.f2646e = C0514d.a();
    }

    private static boolean A(File file, R.a aVar) {
        String canonicalPath;
        try {
            File externalStorageDirectory = Environment.getExternalStorageDirectory();
            if (externalStorageDirectory == null) {
                return false;
            }
            String string = externalStorageDirectory.toString();
            try {
                canonicalPath = file.getCanonicalPath();
            } catch (IOException e3) {
                e = e3;
                canonicalPath = null;
            }
            try {
                return canonicalPath.contains(string);
            } catch (IOException e4) {
                e = e4;
                aVar.a(a.EnumC0038a.OTHER, f2640f, "failed to read folder to check if external: " + canonicalPath, e);
                return false;
            }
        } catch (Exception e5) {
            aVar.a(a.EnumC0038a.OTHER, f2640f, "failed to get the external storage directory!", e5);
            return false;
        }
    }

    private void B(File file, String str) throws c.a {
        try {
            W.c.a(file);
        } catch (c.a e3) {
            this.f2645d.a(a.EnumC0038a.WRITE_CREATE_DIR, f2640f, str, e3);
            throw e3;
        }
    }

    private boolean C(String str, boolean z3) {
        File fileS = s(str);
        boolean zExists = fileS.exists();
        if (z3 && zExists) {
            fileS.setLastModified(this.f2646e.now());
        }
        return zExists;
    }

    private void D() {
        if (this.f2642a.exists()) {
            if (this.f2644c.exists()) {
                return;
            } else {
                W.a.b(this.f2642a);
            }
        }
        try {
            W.c.a(this.f2644c);
        } catch (c.a unused) {
            this.f2645d.a(a.EnumC0038a.WRITE_CREATE_DIR, f2640f, "version directory could not be created: " + this.f2644c, null);
        }
    }

    private long r(File file) {
        if (!file.exists()) {
            return 0L;
        }
        long length = file.length();
        if (file.delete()) {
            return length;
        }
        return -1L;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static String u(String str) {
        if (".cnt".equals(str)) {
            return ".cnt";
        }
        if (".tmp".equals(str)) {
            return ".tmp";
        }
        return null;
    }

    private String v(String str) {
        c cVar = new c(".cnt", str);
        return cVar.c(y(cVar.f2654b));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public c w(File file) {
        c cVarB = c.b(file);
        if (cVarB != null && x(cVarB.f2654b).equals(file.getParentFile())) {
            return cVarB;
        }
        return null;
    }

    private File x(String str) {
        return new File(y(str));
    }

    private String y(String str) {
        return this.f2644c + File.separator + String.valueOf(Math.abs(str.hashCode() % 100));
    }

    static String z(int i3) {
        return String.format(null, "%s.ols%d.%d", "v2", 100, Integer.valueOf(i3));
    }

    @Override // S.f
    public void a() {
        W.a.a(this.f2642a);
    }

    @Override // S.f
    public boolean c() {
        return this.f2643b;
    }

    @Override // S.f
    public void d() {
        W.a.c(this.f2642a, new f());
    }

    @Override // S.f
    public long e(f.a aVar) {
        return r(((b) aVar).b().d());
    }

    @Override // S.f
    public f.b f(String str, Object obj) throws IOException {
        c cVar = new c(".tmp", str);
        File fileX = x(cVar.f2654b);
        if (!fileX.exists()) {
            B(fileX, "insert");
        }
        try {
            return new e(str, cVar.a(fileX));
        } catch (IOException e3) {
            this.f2645d.a(a.EnumC0038a.WRITE_CREATE_TEMPFILE, f2640f, "insert", e3);
            throw e3;
        }
    }

    @Override // S.f
    public boolean g(String str, Object obj) {
        return C(str, true);
    }

    @Override // S.f
    public long h(String str) {
        return r(s(str));
    }

    @Override // S.f
    public boolean i(String str, Object obj) {
        return C(str, false);
    }

    @Override // S.f
    public Q.a j(String str, Object obj) {
        File fileS = s(str);
        if (!fileS.exists()) {
            return null;
        }
        fileS.setLastModified(this.f2646e.now());
        return Q.b.c(fileS);
    }

    File s(String str) {
        return new File(v(str));
    }

    @Override // S.f
    /* JADX INFO: renamed from: t, reason: merged with bridge method [inline-methods] */
    public List b() {
        C0039a c0039a = new C0039a();
        W.a.c(this.f2644c, c0039a);
        return c0039a.d();
    }
}

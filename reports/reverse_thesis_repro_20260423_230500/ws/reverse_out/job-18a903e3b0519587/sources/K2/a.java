package K2;

import Q2.D;
import Q2.F;
import Q2.t;
import Q2.u;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public interface a {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final C0025a f1690b = new C0025a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final a f1689a = new C0025a.C0026a();

    /* JADX INFO: renamed from: K2.a$a, reason: collision with other inner class name */
    public static final class C0025a {

        /* JADX INFO: renamed from: K2.a$a$a, reason: collision with other inner class name */
        private static final class C0026a implements a {
            @Override // K2.a
            public void a(File file) throws IOException {
                j.f(file, "file");
                if (file.delete() || !file.exists()) {
                    return;
                }
                throw new IOException("failed to delete " + file);
            }

            @Override // K2.a
            public F b(File file) {
                j.f(file, "file");
                return t.k(file);
            }

            @Override // K2.a
            public D c(File file) {
                j.f(file, "file");
                try {
                    return u.g(file, false, 1, null);
                } catch (FileNotFoundException unused) {
                    file.getParentFile().mkdirs();
                    return u.g(file, false, 1, null);
                }
            }

            @Override // K2.a
            public void d(File file) throws IOException {
                j.f(file, "directory");
                File[] fileArrListFiles = file.listFiles();
                if (fileArrListFiles == null) {
                    throw new IOException("not a readable directory: " + file);
                }
                for (File file2 : fileArrListFiles) {
                    j.e(file2, "file");
                    if (file2.isDirectory()) {
                        d(file2);
                    }
                    if (!file2.delete()) {
                        throw new IOException("failed to delete " + file2);
                    }
                }
            }

            @Override // K2.a
            public D e(File file) {
                j.f(file, "file");
                try {
                    return t.a(file);
                } catch (FileNotFoundException unused) {
                    file.getParentFile().mkdirs();
                    return t.a(file);
                }
            }

            @Override // K2.a
            public boolean f(File file) {
                j.f(file, "file");
                return file.exists();
            }

            @Override // K2.a
            public void g(File file, File file2) throws IOException {
                j.f(file, "from");
                j.f(file2, "to");
                a(file2);
                if (file.renameTo(file2)) {
                    return;
                }
                throw new IOException("failed to rename " + file + " to " + file2);
            }

            @Override // K2.a
            public long h(File file) {
                j.f(file, "file");
                return file.length();
            }

            public String toString() {
                return "FileSystem.SYSTEM";
            }
        }

        private C0025a() {
        }

        public /* synthetic */ C0025a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    void a(File file);

    F b(File file);

    D c(File file);

    void d(File file);

    D e(File file);

    boolean f(File file);

    void g(File file, File file2);

    long h(File file);
}

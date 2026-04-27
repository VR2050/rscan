package Q;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class b implements Q.a {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final a f2313b = new a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final File f2314a;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final b a(File file) {
            j.f(file, "file");
            return new b(file, null);
        }

        public final b b(File file) {
            DefaultConstructorMarker defaultConstructorMarker = null;
            if (file != null) {
                return new b(file, defaultConstructorMarker);
            }
            return null;
        }

        private a() {
        }
    }

    public /* synthetic */ b(File file, DefaultConstructorMarker defaultConstructorMarker) {
        this(file);
    }

    public static final b b(File file) {
        return f2313b.a(file);
    }

    public static final b c(File file) {
        return f2313b.b(file);
    }

    @Override // Q.a
    public InputStream a() {
        return new FileInputStream(this.f2314a);
    }

    public final File d() {
        return this.f2314a;
    }

    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof b)) {
            return false;
        }
        return j.b(this.f2314a, ((b) obj).f2314a);
    }

    public int hashCode() {
        return this.f2314a.hashCode();
    }

    @Override // Q.a
    public long size() {
        return this.f2314a.length();
    }

    private b(File file) {
        this.f2314a = file;
    }
}

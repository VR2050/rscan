package androidx.core.view;

import android.content.ClipData;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.view.ContentInfo;
import java.util.Objects;

/* JADX INFO: renamed from: androidx.core.view.d, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0258d {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final f f4450a;

    /* JADX INFO: renamed from: androidx.core.view.d$a */
    public static final class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final c f4451a;

        public a(ClipData clipData, int i3) {
            if (Build.VERSION.SDK_INT >= 31) {
                this.f4451a = new b(clipData, i3);
            } else {
                this.f4451a = new C0066d(clipData, i3);
            }
        }

        public C0258d a() {
            return this.f4451a.a();
        }

        public a b(Bundle bundle) {
            this.f4451a.b(bundle);
            return this;
        }

        public a c(int i3) {
            this.f4451a.d(i3);
            return this;
        }

        public a d(Uri uri) {
            this.f4451a.c(uri);
            return this;
        }
    }

    /* JADX INFO: renamed from: androidx.core.view.d$b */
    private static final class b implements c {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final ContentInfo.Builder f4452a;

        b(ClipData clipData, int i3) {
            this.f4452a = AbstractC0264g.a(clipData, i3);
        }

        @Override // androidx.core.view.C0258d.c
        public C0258d a() {
            return new C0258d(new e(this.f4452a.build()));
        }

        @Override // androidx.core.view.C0258d.c
        public void b(Bundle bundle) {
            this.f4452a.setExtras(bundle);
        }

        @Override // androidx.core.view.C0258d.c
        public void c(Uri uri) {
            this.f4452a.setLinkUri(uri);
        }

        @Override // androidx.core.view.C0258d.c
        public void d(int i3) {
            this.f4452a.setFlags(i3);
        }
    }

    /* JADX INFO: renamed from: androidx.core.view.d$c */
    private interface c {
        C0258d a();

        void b(Bundle bundle);

        void c(Uri uri);

        void d(int i3);
    }

    /* JADX INFO: renamed from: androidx.core.view.d$d, reason: collision with other inner class name */
    private static final class C0066d implements c {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        ClipData f4453a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        int f4454b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        int f4455c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        Uri f4456d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        Bundle f4457e;

        C0066d(ClipData clipData, int i3) {
            this.f4453a = clipData;
            this.f4454b = i3;
        }

        @Override // androidx.core.view.C0258d.c
        public C0258d a() {
            return new C0258d(new g(this));
        }

        @Override // androidx.core.view.C0258d.c
        public void b(Bundle bundle) {
            this.f4457e = bundle;
        }

        @Override // androidx.core.view.C0258d.c
        public void c(Uri uri) {
            this.f4456d = uri;
        }

        @Override // androidx.core.view.C0258d.c
        public void d(int i3) {
            this.f4455c = i3;
        }
    }

    /* JADX INFO: renamed from: androidx.core.view.d$e */
    private static final class e implements f {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final ContentInfo f4458a;

        e(ContentInfo contentInfo) {
            this.f4458a = AbstractC0256c.a(q.g.f(contentInfo));
        }

        @Override // androidx.core.view.C0258d.f
        public ClipData a() {
            return this.f4458a.getClip();
        }

        @Override // androidx.core.view.C0258d.f
        public int b() {
            return this.f4458a.getFlags();
        }

        @Override // androidx.core.view.C0258d.f
        public ContentInfo c() {
            return this.f4458a;
        }

        @Override // androidx.core.view.C0258d.f
        public int d() {
            return this.f4458a.getSource();
        }

        public String toString() {
            return "ContentInfoCompat{" + this.f4458a + "}";
        }
    }

    /* JADX INFO: renamed from: androidx.core.view.d$f */
    private interface f {
        ClipData a();

        int b();

        ContentInfo c();

        int d();
    }

    /* JADX INFO: renamed from: androidx.core.view.d$g */
    private static final class g implements f {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final ClipData f4459a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final int f4460b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final int f4461c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final Uri f4462d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private final Bundle f4463e;

        g(C0066d c0066d) {
            this.f4459a = (ClipData) q.g.f(c0066d.f4453a);
            this.f4460b = q.g.b(c0066d.f4454b, 0, 5, "source");
            this.f4461c = q.g.e(c0066d.f4455c, 1);
            this.f4462d = c0066d.f4456d;
            this.f4463e = c0066d.f4457e;
        }

        @Override // androidx.core.view.C0258d.f
        public ClipData a() {
            return this.f4459a;
        }

        @Override // androidx.core.view.C0258d.f
        public int b() {
            return this.f4461c;
        }

        @Override // androidx.core.view.C0258d.f
        public ContentInfo c() {
            return null;
        }

        @Override // androidx.core.view.C0258d.f
        public int d() {
            return this.f4460b;
        }

        public String toString() {
            String str;
            StringBuilder sb = new StringBuilder();
            sb.append("ContentInfoCompat{clip=");
            sb.append(this.f4459a.getDescription());
            sb.append(", source=");
            sb.append(C0258d.e(this.f4460b));
            sb.append(", flags=");
            sb.append(C0258d.a(this.f4461c));
            if (this.f4462d == null) {
                str = "";
            } else {
                str = ", hasLinkUri(" + this.f4462d.toString().length() + ")";
            }
            sb.append(str);
            sb.append(this.f4463e != null ? ", hasExtras" : "");
            sb.append("}");
            return sb.toString();
        }
    }

    C0258d(f fVar) {
        this.f4450a = fVar;
    }

    static String a(int i3) {
        return (i3 & 1) != 0 ? "FLAG_CONVERT_TO_PLAIN_TEXT" : String.valueOf(i3);
    }

    static String e(int i3) {
        return i3 != 0 ? i3 != 1 ? i3 != 2 ? i3 != 3 ? i3 != 4 ? i3 != 5 ? String.valueOf(i3) : "SOURCE_PROCESS_TEXT" : "SOURCE_AUTOFILL" : "SOURCE_DRAG_AND_DROP" : "SOURCE_INPUT_METHOD" : "SOURCE_CLIPBOARD" : "SOURCE_APP";
    }

    public static C0258d g(ContentInfo contentInfo) {
        return new C0258d(new e(contentInfo));
    }

    public ClipData b() {
        return this.f4450a.a();
    }

    public int c() {
        return this.f4450a.b();
    }

    public int d() {
        return this.f4450a.d();
    }

    public ContentInfo f() {
        ContentInfo contentInfoC = this.f4450a.c();
        Objects.requireNonNull(contentInfoC);
        return AbstractC0256c.a(contentInfoC);
    }

    public String toString() {
        return this.f4450a.toString();
    }
}

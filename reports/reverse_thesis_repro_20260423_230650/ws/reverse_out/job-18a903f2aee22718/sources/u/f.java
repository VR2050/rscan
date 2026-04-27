package u;

import android.content.ClipDescription;
import android.net.Uri;
import android.os.Build;
import android.view.inputmethod.InputContentInfo;

/* JADX INFO: loaded from: classes.dex */
public final class f {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final c f10224a;

    private interface c {
        Object a();

        Uri b();

        void c();

        Uri d();

        ClipDescription getDescription();
    }

    public f(Uri uri, ClipDescription clipDescription, Uri uri2) {
        if (Build.VERSION.SDK_INT >= 25) {
            this.f10224a = new a(uri, clipDescription, uri2);
        } else {
            this.f10224a = new b(uri, clipDescription, uri2);
        }
    }

    public static f f(Object obj) {
        if (obj != null && Build.VERSION.SDK_INT >= 25) {
            return new f(new a(obj));
        }
        return null;
    }

    public Uri a() {
        return this.f10224a.b();
    }

    public ClipDescription b() {
        return this.f10224a.getDescription();
    }

    public Uri c() {
        return this.f10224a.d();
    }

    public void d() {
        this.f10224a.c();
    }

    public Object e() {
        return this.f10224a.a();
    }

    private static final class a implements c {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final InputContentInfo f10225a;

        a(Object obj) {
            this.f10225a = (InputContentInfo) obj;
        }

        @Override // u.f.c
        public Object a() {
            return this.f10225a;
        }

        @Override // u.f.c
        public Uri b() {
            return this.f10225a.getContentUri();
        }

        @Override // u.f.c
        public void c() {
            this.f10225a.requestPermission();
        }

        @Override // u.f.c
        public Uri d() {
            return this.f10225a.getLinkUri();
        }

        @Override // u.f.c
        public ClipDescription getDescription() {
            return this.f10225a.getDescription();
        }

        a(Uri uri, ClipDescription clipDescription, Uri uri2) {
            this.f10225a = new InputContentInfo(uri, clipDescription, uri2);
        }
    }

    private f(c cVar) {
        this.f10224a = cVar;
    }

    private static final class b implements c {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final Uri f10226a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final ClipDescription f10227b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final Uri f10228c;

        b(Uri uri, ClipDescription clipDescription, Uri uri2) {
            this.f10226a = uri;
            this.f10227b = clipDescription;
            this.f10228c = uri2;
        }

        @Override // u.f.c
        public Object a() {
            return null;
        }

        @Override // u.f.c
        public Uri b() {
            return this.f10226a;
        }

        @Override // u.f.c
        public Uri d() {
            return this.f10228c;
        }

        @Override // u.f.c
        public ClipDescription getDescription() {
            return this.f10227b;
        }

        @Override // u.f.c
        public void c() {
        }
    }
}

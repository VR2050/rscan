package H0;

import android.graphics.Bitmap;
import android.graphics.ColorSpace;

/* JADX INFO: loaded from: classes.dex */
public class e {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private int f1002a = 100;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private int f1003b = Integer.MAX_VALUE;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private boolean f1004c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private boolean f1005d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private boolean f1006e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private boolean f1007f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private boolean f1008g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private Bitmap.Config f1009h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private Bitmap.Config f1010i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private L0.c f1011j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private ColorSpace f1012k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private boolean f1013l;

    public e() {
        Bitmap.Config config = Bitmap.Config.ARGB_8888;
        this.f1009h = config;
        this.f1010i = config;
    }

    public d a() {
        return new d(this);
    }

    public Bitmap.Config b() {
        return this.f1010i;
    }

    public Bitmap.Config c() {
        return this.f1009h;
    }

    public W0.a d() {
        return null;
    }

    public ColorSpace e() {
        return this.f1012k;
    }

    public L0.c f() {
        return this.f1011j;
    }

    public boolean g() {
        return this.f1007f;
    }

    public boolean h() {
        return this.f1004c;
    }

    public boolean i() {
        return this.f1013l;
    }

    public boolean j() {
        return this.f1008g;
    }

    public int k() {
        return this.f1003b;
    }

    public int l() {
        return this.f1002a;
    }

    public boolean m() {
        return this.f1006e;
    }

    public boolean n() {
        return this.f1005d;
    }
}

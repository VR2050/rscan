package com.facebook.react.devsupport;

import android.view.View;
import android.widget.FrameLayout;
import android.widget.TextView;
import c1.AbstractC0339k;
import c1.AbstractC0341m;
import com.facebook.react.bridge.ReactContext;
import java.util.Arrays;
import java.util.Locale;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class L extends FrameLayout {

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public static final a f6769e = new a(null);

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final TextView f6770b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final com.facebook.react.modules.debug.h f6771c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final b f6772d;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    private final class b implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private boolean f6773b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private int f6774c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private int f6775d;

        public b() {
        }

        public final void a() {
            this.f6773b = false;
            L.this.post(this);
        }

        public final void b() {
            this.f6773b = true;
        }

        @Override // java.lang.Runnable
        public void run() {
            if (this.f6773b) {
                return;
            }
            this.f6774c += L.this.f6771c.d() - L.this.f6771c.g();
            this.f6775d += L.this.f6771c.c();
            L l3 = L.this;
            l3.c(l3.f6771c.e(), L.this.f6771c.f(), this.f6774c, this.f6775d);
            L.this.f6771c.j();
            L.this.postDelayed(this, 500L);
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public L(ReactContext reactContext) {
        super(reactContext);
        t2.j.c(reactContext);
        View.inflate(reactContext, AbstractC0341m.f5606c, this);
        View viewFindViewById = findViewById(AbstractC0339k.f5591o);
        t2.j.d(viewFindViewById, "null cannot be cast to non-null type android.widget.TextView");
        this.f6770b = (TextView) viewFindViewById;
        this.f6771c = new com.facebook.react.modules.debug.h(reactContext);
        this.f6772d = new b();
        c(0.0d, 0.0d, 0, 0);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void c(double d3, double d4, int i3, int i4) {
        t2.w wVar = t2.w.f10219a;
        String str = String.format(Locale.US, "UI: %.1f fps\n%d dropped so far\n%d stutters (4+) so far\nJS: %.1f fps", Arrays.copyOf(new Object[]{Double.valueOf(d3), Integer.valueOf(i3), Integer.valueOf(i4), Double.valueOf(d4)}, 4));
        t2.j.e(str, "format(...)");
        this.f6770b.setText(str);
        Y.a.b("ReactNative", str);
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        this.f6771c.j();
        com.facebook.react.modules.debug.h.l(this.f6771c, 0.0d, 1, null);
        this.f6772d.a();
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        this.f6771c.n();
        this.f6772d.b();
    }
}

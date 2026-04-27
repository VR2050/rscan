package N1;

import android.content.Context;
import android.graphics.Outline;
import android.graphics.Path;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.LayerDrawable;
import android.os.Build;
import com.facebook.react.uimanager.C0444f0;
import i2.AbstractC0586n;
import java.util.ArrayList;
import java.util.List;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class g extends LayerDrawable {

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    public static final a f1976m = new a(null);

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final Context f1977b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final Drawable f1978c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final List f1979d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final e f1980e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final N1.a f1981f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final c f1982g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final Drawable f1983h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final List f1984i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final k f1985j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private Q1.c f1986k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private Q1.e f1987l;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final Drawable[] b(Drawable drawable, List list, e eVar, N1.a aVar, c cVar, Drawable drawable2, List list2, k kVar) {
            ArrayList arrayList = new ArrayList();
            if (drawable != null) {
                arrayList.add(drawable);
            }
            arrayList.addAll(AbstractC0586n.v(list));
            if (eVar != null) {
                arrayList.add(eVar);
            }
            if (aVar != null) {
                arrayList.add(aVar);
            }
            if (cVar != null) {
                arrayList.add(cVar);
            }
            if (drawable2 != null) {
                arrayList.add(drawable2);
            }
            arrayList.addAll(AbstractC0586n.v(list2));
            if (kVar != null) {
                arrayList.add(kVar);
            }
            return (Drawable[]) arrayList.toArray(new Drawable[0]);
        }

        private a() {
        }
    }

    public /* synthetic */ g(Context context, Drawable drawable, List list, e eVar, N1.a aVar, c cVar, Drawable drawable2, List list2, k kVar, Q1.c cVar2, Q1.e eVar2, int i3, DefaultConstructorMarker defaultConstructorMarker) {
        this(context, (i3 & 2) != 0 ? null : drawable, (i3 & 4) != 0 ? AbstractC0586n.g() : list, (i3 & 8) != 0 ? null : eVar, (i3 & 16) != 0 ? null : aVar, (i3 & 32) != 0 ? null : cVar, (i3 & 64) != 0 ? null : drawable2, (i3 & 128) != 0 ? AbstractC0586n.g() : list2, (i3 & 256) != 0 ? null : kVar, (i3 & 512) != 0 ? null : cVar2, (i3 & 1024) == 0 ? eVar2 : null);
    }

    public final N1.a a() {
        return this.f1981f;
    }

    public final c b() {
        return this.f1982g;
    }

    public final Q1.c c() {
        return this.f1986k;
    }

    public final Q1.e d() {
        return this.f1987l;
    }

    public final e e() {
        return this.f1980e;
    }

    public final List f() {
        return this.f1984i;
    }

    public final Drawable g() {
        return this.f1978c;
    }

    @Override // android.graphics.drawable.LayerDrawable, android.graphics.drawable.Drawable
    public void getOutline(Outline outline) {
        t2.j.f(outline, "outline");
        Q1.e eVar = this.f1987l;
        if (eVar == null || !eVar.c()) {
            outline.setRect(getBounds());
            return;
        }
        Path path = new Path();
        Q1.e eVar2 = this.f1987l;
        Q1.j jVarD = eVar2 != null ? eVar2.d(getLayoutDirection(), this.f1977b, getBounds().width(), getBounds().height()) : null;
        Q1.c cVar = this.f1986k;
        RectF rectFA = cVar != null ? cVar.a(getLayoutDirection(), this.f1977b) : null;
        if (jVarD != null) {
            RectF rectF = new RectF(getBounds());
            C0444f0 c0444f0 = C0444f0.f7603a;
            path.addRoundRect(rectF, new float[]{c0444f0.b(jVarD.c().a() + (rectFA != null ? rectFA.left : 0.0f)), c0444f0.b(jVarD.c().b() + (rectFA != null ? rectFA.top : 0.0f)), c0444f0.b(jVarD.d().a() + (rectFA != null ? rectFA.right : 0.0f)), c0444f0.b(jVarD.d().b() + (rectFA != null ? rectFA.top : 0.0f)), c0444f0.b(jVarD.b().a() + (rectFA != null ? rectFA.right : 0.0f)), c0444f0.b(jVarD.b().b() + (rectFA != null ? rectFA.bottom : 0.0f)), c0444f0.b(jVarD.a().a() + (rectFA != null ? rectFA.left : 0.0f)), c0444f0.b(jVarD.a().b() + (rectFA != null ? rectFA.bottom : 0.0f))}, Path.Direction.CW);
        }
        if (Build.VERSION.SDK_INT >= 30) {
            outline.setPath(path);
        } else {
            outline.setConvexPath(path);
        }
    }

    public final List h() {
        return this.f1979d;
    }

    public final k i() {
        return this.f1985j;
    }

    public final void j(Q1.c cVar) {
        this.f1986k = cVar;
    }

    public final void k(Q1.e eVar) {
        this.f1987l = eVar;
    }

    public final g l(N1.a aVar) {
        return new g(this.f1977b, this.f1978c, this.f1979d, this.f1980e, aVar, this.f1982g, this.f1983h, this.f1984i, this.f1985j, this.f1986k, this.f1987l);
    }

    public final g m(c cVar) {
        t2.j.f(cVar, "border");
        return new g(this.f1977b, this.f1978c, this.f1979d, this.f1980e, this.f1981f, cVar, this.f1983h, this.f1984i, this.f1985j, this.f1986k, this.f1987l);
    }

    public final g n(e eVar) {
        return new g(this.f1977b, this.f1978c, this.f1979d, eVar, this.f1981f, this.f1982g, this.f1983h, this.f1984i, this.f1985j, this.f1986k, this.f1987l);
    }

    public final g o(Drawable drawable) {
        return new g(this.f1977b, this.f1978c, this.f1979d, this.f1980e, this.f1981f, this.f1982g, drawable, this.f1984i, this.f1985j, this.f1986k, this.f1987l);
    }

    public final g p(k kVar) {
        t2.j.f(kVar, "outline");
        return new g(this.f1977b, this.f1978c, this.f1979d, this.f1980e, this.f1981f, this.f1982g, this.f1983h, this.f1984i, kVar, this.f1986k, this.f1987l);
    }

    public final g q(List list, List list2) {
        t2.j.f(list, "outerShadows");
        t2.j.f(list2, "innerShadows");
        return new g(this.f1977b, this.f1978c, list, this.f1980e, this.f1981f, this.f1982g, this.f1983h, list2, this.f1985j, this.f1986k, this.f1987l);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(Context context, Drawable drawable, List list, e eVar, N1.a aVar, c cVar, Drawable drawable2, List list2, k kVar, Q1.c cVar2, Q1.e eVar2) {
        super(f1976m.b(drawable, list, eVar, aVar, cVar, drawable2, list2, kVar));
        t2.j.f(context, "context");
        t2.j.f(list, "outerShadows");
        t2.j.f(list2, "innerShadows");
        this.f1977b = context;
        this.f1978c = drawable;
        this.f1979d = list;
        this.f1980e = eVar;
        this.f1981f = aVar;
        this.f1982g = cVar;
        this.f1983h = drawable2;
        this.f1984i = list2;
        this.f1985j = kVar;
        this.f1986k = cVar2;
        this.f1987l = eVar2;
        setPaddingMode(1);
    }
}

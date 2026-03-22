package p005b.p143g.p144a;

import android.content.Context;
import android.content.ContextWrapper;
import androidx.annotation.GuardedBy;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;
import java.util.List;
import java.util.Map;
import p005b.p143g.p144a.ComponentCallbacks2C1553c;
import p005b.p143g.p144a.p147m.p150t.C1644l;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1612b;
import p005b.p143g.p144a.p166q.C1779f;
import p005b.p143g.p144a.p166q.InterfaceC1778e;
import p005b.p143g.p144a.p166q.p167i.C1788g;

/* renamed from: b.g.a.e */
/* loaded from: classes.dex */
public class C1555e extends ContextWrapper {

    /* renamed from: a */
    @VisibleForTesting
    public static final AbstractC1560j<?, ?> f1834a = new C1552b();

    /* renamed from: b */
    public final InterfaceC1612b f1835b;

    /* renamed from: c */
    public final C1557g f1836c;

    /* renamed from: d */
    public final C1788g f1837d;

    /* renamed from: e */
    public final ComponentCallbacks2C1553c.a f1838e;

    /* renamed from: f */
    public final List<InterfaceC1778e<Object>> f1839f;

    /* renamed from: g */
    public final Map<Class<?>, AbstractC1560j<?, ?>> f1840g;

    /* renamed from: h */
    public final C1644l f1841h;

    /* renamed from: i */
    public final boolean f1842i;

    /* renamed from: j */
    public final int f1843j;

    /* renamed from: k */
    @Nullable
    @GuardedBy("this")
    public C1779f f1844k;

    public C1555e(@NonNull Context context, @NonNull InterfaceC1612b interfaceC1612b, @NonNull C1557g c1557g, @NonNull C1788g c1788g, @NonNull ComponentCallbacks2C1553c.a aVar, @NonNull Map<Class<?>, AbstractC1560j<?, ?>> map, @NonNull List<InterfaceC1778e<Object>> list, @NonNull C1644l c1644l, boolean z, int i2) {
        super(context.getApplicationContext());
        this.f1835b = interfaceC1612b;
        this.f1836c = c1557g;
        this.f1837d = c1788g;
        this.f1838e = aVar;
        this.f1839f = list;
        this.f1840g = map;
        this.f1841h = c1644l;
        this.f1842i = z;
        this.f1843j = i2;
    }
}

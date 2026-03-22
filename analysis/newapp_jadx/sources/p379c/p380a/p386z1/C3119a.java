package p379c.p380a.p386z1;

import android.os.Handler;
import android.os.Looper;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import kotlin.ranges.RangesKt___RangesKt;
import kotlin.time.DurationKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p379c.p380a.AbstractC3077l1;
import p379c.p380a.C3069j;
import p379c.p380a.InterfaceC3066i;
import p379c.p380a.InterfaceC3070j0;

/* renamed from: c.a.z1.a */
/* loaded from: classes2.dex */
public final class C3119a extends AbstractC3120b implements InterfaceC3070j0 {
    public volatile C3119a _immediate;

    /* renamed from: c */
    @NotNull
    public final C3119a f8478c;

    /* renamed from: e */
    public final Handler f8479e;

    /* renamed from: f */
    public final String f8480f;

    /* renamed from: g */
    public final boolean f8481g;

    /* renamed from: c.a.z1.a$a */
    public static final class a implements Runnable {

        /* renamed from: e */
        public final /* synthetic */ InterfaceC3066i f8483e;

        public a(InterfaceC3066i interfaceC3066i) {
            this.f8483e = interfaceC3066i;
        }

        @Override // java.lang.Runnable
        public final void run() {
            this.f8483e.mo3565i(C3119a.this, Unit.INSTANCE);
        }
    }

    /* renamed from: c.a.z1.a$b */
    public static final class b extends Lambda implements Function1<Throwable, Unit> {

        /* renamed from: e */
        public final /* synthetic */ Runnable f8485e;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public b(Runnable runnable) {
            super(1);
            this.f8485e = runnable;
        }

        @Override // kotlin.jvm.functions.Function1
        public Unit invoke(Throwable th) {
            C3119a.this.f8479e.removeCallbacks(this.f8485e);
            return Unit.INSTANCE;
        }
    }

    public C3119a(Handler handler, String str, boolean z) {
        super(null);
        this.f8479e = handler;
        this.f8480f = str;
        this.f8481g = z;
        this._immediate = z ? this : null;
        C3119a c3119a = this._immediate;
        if (c3119a == null) {
            c3119a = new C3119a(handler, str, true);
            this._immediate = c3119a;
            Unit unit = Unit.INSTANCE;
        }
        this.f8478c = c3119a;
    }

    @Override // p379c.p380a.AbstractC3077l1
    /* renamed from: U */
    public AbstractC3077l1 mo3620U() {
        return this.f8478c;
    }

    @Override // p379c.p380a.AbstractC3036c0
    public void dispatch(@NotNull CoroutineContext coroutineContext, @NotNull Runnable runnable) {
        this.f8479e.post(runnable);
    }

    @Override // p379c.p380a.InterfaceC3070j0
    /* renamed from: e */
    public void mo3617e(long j2, @NotNull InterfaceC3066i<? super Unit> interfaceC3066i) {
        a aVar = new a(interfaceC3066i);
        this.f8479e.postDelayed(aVar, RangesKt___RangesKt.coerceAtMost(j2, DurationKt.MAX_MILLIS));
        ((C3069j) interfaceC3066i).mo3562f(new b(aVar));
    }

    public boolean equals(@Nullable Object obj) {
        return (obj instanceof C3119a) && ((C3119a) obj).f8479e == this.f8479e;
    }

    public int hashCode() {
        return System.identityHashCode(this.f8479e);
    }

    @Override // p379c.p380a.AbstractC3036c0
    public boolean isDispatchNeeded(@NotNull CoroutineContext coroutineContext) {
        return !this.f8481g || (Intrinsics.areEqual(Looper.myLooper(), this.f8479e.getLooper()) ^ true);
    }

    @Override // p379c.p380a.AbstractC3077l1, p379c.p380a.AbstractC3036c0
    @NotNull
    public String toString() {
        String m3621V = m3621V();
        if (m3621V != null) {
            return m3621V;
        }
        String str = this.f8480f;
        if (str == null) {
            str = this.f8479e.toString();
        }
        return this.f8481g ? C1499a.m637w(str, ".immediate") : str;
    }
}

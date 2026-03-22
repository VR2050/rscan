package p379c.p380a;

import kotlin.Result;
import kotlin.ResultKt;
import kotlin.Unit;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: c.a.r1 */
/* loaded from: classes2.dex */
public final class C3095r1<T> extends AbstractC3065h1<C3068i1> {

    /* renamed from: h */
    public final C3069j<T> f8454h;

    /* JADX WARN: Multi-variable type inference failed */
    public C3095r1(@NotNull C3068i1 c3068i1, @NotNull C3069j<? super T> c3069j) {
        super(c3068i1);
        this.f8454h = c3069j;
    }

    @Override // kotlin.jvm.functions.Function1
    public /* bridge */ /* synthetic */ Unit invoke(Throwable th) {
        mo3514r(th);
        return Unit.INSTANCE;
    }

    @Override // p379c.p380a.AbstractC3114y
    /* renamed from: r */
    public void mo3514r(@Nullable Throwable th) {
        Object m3576L = ((C3068i1) this.f8403g).m3576L();
        if (m3576L instanceof C3108w) {
            C3069j<T> c3069j = this.f8454h;
            Throwable th2 = ((C3108w) m3576L).f8470b;
            Result.Companion companion = Result.INSTANCE;
            c3069j.resumeWith(Result.m6055constructorimpl(ResultKt.createFailure(th2)));
            return;
        }
        C3069j<T> c3069j2 = this.f8454h;
        Object m3618a = C3071j1.m3618a(m3576L);
        Result.Companion companion2 = Result.INSTANCE;
        c3069j2.resumeWith(Result.m6055constructorimpl(m3618a));
    }

    @Override // p379c.p380a.p381a.C2961j
    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("ResumeAwaitOnCompletion[");
        m586H.append(this.f8454h);
        m586H.append(']');
        return m586H.toString();
    }
}

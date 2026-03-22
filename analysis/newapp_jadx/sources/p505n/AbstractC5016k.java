package p505n;

import javax.annotation.Nullable;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsJvmKt;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import kotlin.coroutines.jvm.internal.DebugProbesKt;
import p379c.p380a.C3069j;
import p458k.AbstractC4393m0;
import p458k.InterfaceC4378f;
import p476m.p496b.p497a.InterfaceC4913g;

/* renamed from: n.k */
/* loaded from: classes3.dex */
public abstract class AbstractC5016k<ResponseT, ReturnT> extends AbstractC4978a0<ReturnT> {

    /* renamed from: a */
    public final C5029x f12827a;

    /* renamed from: b */
    public final InterfaceC4378f.a f12828b;

    /* renamed from: c */
    public final InterfaceC5013h<AbstractC4393m0, ResponseT> f12829c;

    /* renamed from: n.k$a */
    public static final class a<ResponseT, ReturnT> extends AbstractC5016k<ResponseT, ReturnT> {

        /* renamed from: d */
        public final InterfaceC4985e<ResponseT, ReturnT> f12830d;

        public a(C5029x c5029x, InterfaceC4378f.a aVar, InterfaceC5013h<AbstractC4393m0, ResponseT> interfaceC5013h, InterfaceC4985e<ResponseT, ReturnT> interfaceC4985e) {
            super(c5029x, aVar, interfaceC5013h);
            this.f12830d = interfaceC4985e;
        }

        @Override // p505n.AbstractC5016k
        /* renamed from: c */
        public ReturnT mo5670c(InterfaceC4983d<ResponseT> interfaceC4983d, Object[] objArr) {
            return this.f12830d.mo278b(interfaceC4983d);
        }
    }

    /* renamed from: n.k$b */
    public static final class b<ResponseT> extends AbstractC5016k<ResponseT, Object> {

        /* renamed from: d */
        public final InterfaceC4985e<ResponseT, InterfaceC4983d<ResponseT>> f12831d;

        public b(C5029x c5029x, InterfaceC4378f.a aVar, InterfaceC5013h<AbstractC4393m0, ResponseT> interfaceC5013h, InterfaceC4985e<ResponseT, InterfaceC4983d<ResponseT>> interfaceC4985e, boolean z) {
            super(c5029x, aVar, interfaceC5013h);
            this.f12831d = interfaceC4985e;
        }

        @Override // p505n.AbstractC5016k
        /* renamed from: c */
        public Object mo5670c(InterfaceC4983d<ResponseT> interfaceC4983d, Object[] objArr) {
            InterfaceC4983d<ResponseT> mo278b = this.f12831d.mo278b(interfaceC4983d);
            Continuation continuation = (Continuation) objArr[objArr.length - 1];
            try {
                C3069j c3069j = new C3069j(IntrinsicsKt__IntrinsicsJvmKt.intercepted(continuation), 1);
                c3069j.mo3562f(new C5018m(mo278b));
                mo278b.mo5652o(new C5019n(c3069j));
                Object m3612u = c3069j.m3612u();
                if (m3612u == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()) {
                    DebugProbesKt.probeCoroutineSuspended(continuation);
                }
                return m3612u;
            } catch (Exception e2) {
                return InterfaceC4913g.a.m5583a(e2, continuation);
            }
        }
    }

    /* renamed from: n.k$c */
    public static final class c<ResponseT> extends AbstractC5016k<ResponseT, Object> {

        /* renamed from: d */
        public final InterfaceC4985e<ResponseT, InterfaceC4983d<ResponseT>> f12832d;

        public c(C5029x c5029x, InterfaceC4378f.a aVar, InterfaceC5013h<AbstractC4393m0, ResponseT> interfaceC5013h, InterfaceC4985e<ResponseT, InterfaceC4983d<ResponseT>> interfaceC4985e) {
            super(c5029x, aVar, interfaceC5013h);
            this.f12832d = interfaceC4985e;
        }

        @Override // p505n.AbstractC5016k
        /* renamed from: c */
        public Object mo5670c(InterfaceC4983d<ResponseT> interfaceC4983d, Object[] objArr) {
            InterfaceC4983d<ResponseT> mo278b = this.f12832d.mo278b(interfaceC4983d);
            Continuation continuation = (Continuation) objArr[objArr.length - 1];
            try {
                C3069j c3069j = new C3069j(IntrinsicsKt__IntrinsicsJvmKt.intercepted(continuation), 1);
                c3069j.mo3562f(new C5020o(mo278b));
                mo278b.mo5652o(new C5021p(c3069j));
                Object m3612u = c3069j.m3612u();
                if (m3612u == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()) {
                    DebugProbesKt.probeCoroutineSuspended(continuation);
                }
                return m3612u;
            } catch (Exception e2) {
                return InterfaceC4913g.a.m5583a(e2, continuation);
            }
        }
    }

    public AbstractC5016k(C5029x c5029x, InterfaceC4378f.a aVar, InterfaceC5013h<AbstractC4393m0, ResponseT> interfaceC5013h) {
        this.f12827a = c5029x;
        this.f12828b = aVar;
        this.f12829c = interfaceC5013h;
    }

    @Override // p505n.AbstractC4978a0
    @Nullable
    /* renamed from: a */
    public final ReturnT mo5649a(Object[] objArr) {
        return mo5670c(new C5022q(this.f12827a, objArr, this.f12828b, this.f12829c), objArr);
    }

    @Nullable
    /* renamed from: c */
    public abstract ReturnT mo5670c(InterfaceC4983d<ResponseT> interfaceC4983d, Object[] objArr);
}

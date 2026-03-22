package p379c.p380a.p383b2.p384n;

import java.util.ArrayList;
import kotlin.ResultKt;
import kotlin.Unit;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.CoroutineContext;
import kotlin.coroutines.EmptyCoroutineContext;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.coroutines.jvm.internal.SuspendLambda;
import kotlin.jvm.JvmField;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.InterfaceC3055e0;
import p379c.p380a.p382a2.C2990m;
import p379c.p380a.p382a2.EnumC2982e;
import p379c.p380a.p382a2.InterfaceC2992o;
import p379c.p380a.p382a2.InterfaceC2994q;
import p379c.p380a.p383b2.InterfaceC3006b;
import p379c.p380a.p383b2.InterfaceC3007c;

/* renamed from: c.a.b2.n.b */
/* loaded from: classes2.dex */
public abstract class AbstractC3019b<T> implements InterfaceC3026i<T> {

    /* renamed from: a */
    @JvmField
    @NotNull
    public final CoroutineContext f8267a;

    /* renamed from: b */
    @JvmField
    public final int f8268b;

    /* renamed from: c */
    @JvmField
    @NotNull
    public final EnumC2982e f8269c;

    @DebugMetadata(m5319c = "kotlinx.coroutines.flow.internal.ChannelFlow$collect$2", m5320f = "ChannelFlow.kt", m5321i = {0}, m5322l = {135}, m5323m = "invokeSuspend", m5324n = {"$this$coroutineScope"}, m5325s = {"L$0"})
    /* renamed from: c.a.b2.n.b$a */
    public static final class a extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {

        /* renamed from: c */
        public InterfaceC3055e0 f8270c;

        /* renamed from: e */
        public Object f8271e;

        /* renamed from: f */
        public int f8272f;

        /* renamed from: h */
        public final /* synthetic */ InterfaceC3007c f8274h;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public a(InterfaceC3007c interfaceC3007c, Continuation continuation) {
            super(2, continuation);
            this.f8274h = interfaceC3007c;
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @NotNull
        public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
            a aVar = new a(this.f8274h, continuation);
            aVar.f8270c = (InterfaceC3055e0) obj;
            return aVar;
        }

        @Override // kotlin.jvm.functions.Function2
        public final Object invoke(InterfaceC3055e0 interfaceC3055e0, Continuation<? super Unit> continuation) {
            a aVar = new a(this.f8274h, continuation);
            aVar.f8270c = interfaceC3055e0;
            return aVar.invokeSuspend(Unit.INSTANCE);
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            Object coroutine_suspended = IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
            int i2 = this.f8272f;
            if (i2 == 0) {
                ResultKt.throwOnFailure(obj);
                InterfaceC3055e0 interfaceC3055e0 = this.f8270c;
                InterfaceC3007c interfaceC3007c = this.f8274h;
                AbstractC3019b abstractC3019b = AbstractC3019b.this;
                CoroutineContext coroutineContext = abstractC3019b.f8267a;
                int i3 = abstractC3019b.f8268b;
                if (i3 == -3) {
                    i3 = -2;
                }
                InterfaceC2994q m3496a = C2990m.m3496a(interfaceC3055e0, coroutineContext, i3, abstractC3019b.f8269c, 3, null, new C3020c(abstractC3019b, null));
                this.f8271e = interfaceC3055e0;
                this.f8272f = 1;
                Object m2440W = C2354n.m2440W(interfaceC3007c, m3496a, true, this);
                if (m2440W != IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()) {
                    m2440W = Unit.INSTANCE;
                }
                if (m2440W == coroutine_suspended) {
                    return coroutine_suspended;
                }
            } else {
                if (i2 != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                ResultKt.throwOnFailure(obj);
            }
            return Unit.INSTANCE;
        }
    }

    public AbstractC3019b(@NotNull CoroutineContext coroutineContext, int i2, @NotNull EnumC2982e enumC2982e) {
        this.f8267a = coroutineContext;
        this.f8268b = i2;
        this.f8269c = enumC2982e;
    }

    @Override // p379c.p380a.p383b2.InterfaceC3006b
    @Nullable
    /* renamed from: a */
    public Object mo289a(@NotNull InterfaceC3007c<? super T> interfaceC3007c, @NotNull Continuation<? super Unit> continuation) {
        Object m2401J = C2354n.m2401J(new a(interfaceC3007c, null), continuation);
        return m2401J == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED() ? m2401J : Unit.INSTANCE;
    }

    @Override // p379c.p380a.p383b2.p384n.InterfaceC3026i
    @NotNull
    /* renamed from: b */
    public InterfaceC3006b<T> mo3516b(@NotNull CoroutineContext coroutineContext, int i2, @NotNull EnumC2982e enumC2982e) {
        CoroutineContext plus = coroutineContext.plus(this.f8267a);
        if (enumC2982e == EnumC2982e.SUSPEND) {
            int i3 = this.f8268b;
            if (i3 != -3) {
                if (i2 != -3) {
                    if (i3 != -2) {
                        if (i2 != -2 && (i3 = i3 + i2) < 0) {
                            i2 = Integer.MAX_VALUE;
                        }
                    }
                }
                i2 = i3;
            }
            enumC2982e = this.f8269c;
        }
        return (Intrinsics.areEqual(plus, this.f8267a) && i2 == this.f8268b && enumC2982e == this.f8269c) ? this : mo3518d(plus, i2, enumC2982e);
    }

    @Nullable
    /* renamed from: c */
    public abstract Object mo3517c(@NotNull InterfaceC2992o<? super T> interfaceC2992o, @NotNull Continuation<? super Unit> continuation);

    @NotNull
    /* renamed from: d */
    public abstract AbstractC3019b<T> mo3518d(@NotNull CoroutineContext coroutineContext, int i2, @NotNull EnumC2982e enumC2982e);

    @NotNull
    public String toString() {
        ArrayList arrayList = new ArrayList(4);
        if (this.f8267a != EmptyCoroutineContext.INSTANCE) {
            StringBuilder m586H = C1499a.m586H("context=");
            m586H.append(this.f8267a);
            arrayList.add(m586H.toString());
        }
        if (this.f8268b != -3) {
            StringBuilder m586H2 = C1499a.m586H("capacity=");
            m586H2.append(this.f8268b);
            arrayList.add(m586H2.toString());
        }
        if (this.f8269c != EnumC2982e.SUSPEND) {
            StringBuilder m586H3 = C1499a.m586H("onBufferOverflow=");
            m586H3.append(this.f8269c);
            arrayList.add(m586H3.toString());
        }
        StringBuilder sb = new StringBuilder();
        sb.append(getClass().getSimpleName());
        sb.append('[');
        return C1499a.m581C(sb, CollectionsKt___CollectionsKt.joinToString$default(arrayList, ", ", null, null, 0, null, null, 62, null), ']');
    }
}

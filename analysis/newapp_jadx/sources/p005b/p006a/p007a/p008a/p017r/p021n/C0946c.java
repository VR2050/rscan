package p005b.p006a.p007a.p008a.p017r.p021n;

import com.jbzd.media.movecartoons.bean.response.VipInfoBean;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import kotlin.coroutines.jvm.internal.ContinuationImpl;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p013o.C0909c;
import p379c.p380a.p383b2.InterfaceC3006b;
import p379c.p380a.p383b2.InterfaceC3007c;

/* renamed from: b.a.a.a.r.n.c */
/* loaded from: classes2.dex */
public final class C0946c implements InterfaceC3006b<C0909c> {

    /* renamed from: a */
    public final /* synthetic */ InterfaceC3006b f478a;

    /* renamed from: b.a.a.a.r.n.c$a */
    public static final class a implements InterfaceC3007c<VipInfoBean> {

        /* renamed from: c */
        public final /* synthetic */ InterfaceC3007c f479c;

        @DebugMetadata(m5319c = "com.jbzd.media.movecartoons.net.repository.ComicsRepository$getVipList$$inlined$map$1$2", m5320f = "ComicsRepository.kt", m5321i = {}, m5322l = {143}, m5323m = "emit", m5324n = {}, m5325s = {})
        /* renamed from: b.a.a.a.r.n.c$a$a, reason: collision with other inner class name */
        public static final class C5102a extends ContinuationImpl {

            /* renamed from: c */
            public /* synthetic */ Object f480c;

            /* renamed from: e */
            public int f481e;

            public C5102a(Continuation continuation) {
                super(continuation);
            }

            @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
            @Nullable
            public final Object invokeSuspend(@NotNull Object obj) {
                this.f480c = obj;
                this.f481e |= Integer.MIN_VALUE;
                return a.this.emit(null, this);
            }
        }

        public a(InterfaceC3007c interfaceC3007c, C0946c c0946c) {
            this.f479c = interfaceC3007c;
        }

        /* JADX WARN: Removed duplicated region for block: B:15:0x0032  */
        /* JADX WARN: Removed duplicated region for block: B:8:0x0023  */
        @Override // p379c.p380a.p383b2.InterfaceC3007c
        @org.jetbrains.annotations.Nullable
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public java.lang.Object emit(com.jbzd.media.movecartoons.bean.response.VipInfoBean r11, @org.jetbrains.annotations.NotNull kotlin.coroutines.Continuation r12) {
            /*
                r10 = this;
                boolean r0 = r12 instanceof p005b.p006a.p007a.p008a.p017r.p021n.C0946c.a.C5102a
                if (r0 == 0) goto L13
                r0 = r12
                b.a.a.a.r.n.c$a$a r0 = (p005b.p006a.p007a.p008a.p017r.p021n.C0946c.a.C5102a) r0
                int r1 = r0.f481e
                r2 = -2147483648(0xffffffff80000000, float:-0.0)
                r3 = r1 & r2
                if (r3 == 0) goto L13
                int r1 = r1 - r2
                r0.f481e = r1
                goto L18
            L13:
                b.a.a.a.r.n.c$a$a r0 = new b.a.a.a.r.n.c$a$a
                r0.<init>(r12)
            L18:
                java.lang.Object r12 = r0.f480c
                java.lang.Object r1 = kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()
                int r2 = r0.f481e
                r3 = 1
                if (r2 == 0) goto L32
                if (r2 != r3) goto L2a
                kotlin.ResultKt.throwOnFailure(r12)
                goto Lc8
            L2a:
                java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
                java.lang.String r12 = "call to 'resume' before 'invoke' with coroutine"
                r11.<init>(r12)
                throw r11
            L32:
                kotlin.ResultKt.throwOnFailure(r12)
                c.a.b2.c r12 = r10.f479c
                com.jbzd.media.movecartoons.bean.response.VipInfoBean r11 = (com.jbzd.media.movecartoons.bean.response.VipInfoBean) r11
                java.util.List r2 = r11.getGroup()
                r4 = 0
                r5 = 0
                if (r2 != 0) goto L43
                r6 = r5
                goto L70
            L43:
                java.util.ArrayList r6 = new java.util.ArrayList
                r6.<init>()
                java.util.Iterator r2 = r2.iterator()
            L4c:
                boolean r7 = r2.hasNext()
                if (r7 == 0) goto L70
                java.lang.Object r7 = r2.next()
                r8 = r7
                com.jbzd.media.movecartoons.bean.response.GroupBean r8 = (com.jbzd.media.movecartoons.bean.response.GroupBean) r8
                int r8 = r8.getLevel()
                if (r8 != r3) goto L61
                r8 = 1
                goto L62
            L61:
                r8 = 0
            L62:
                java.lang.Boolean r8 = kotlin.coroutines.jvm.internal.Boxing.boxBoolean(r8)
                boolean r8 = r8.booleanValue()
                if (r8 == 0) goto L4c
                r6.add(r7)
                goto L4c
            L70:
                if (r6 != 0) goto L76
                java.util.List r6 = kotlin.collections.CollectionsKt__CollectionsKt.emptyList()
            L76:
                java.util.List r2 = r11.getGroup()
                if (r2 != 0) goto L7d
                goto Lab
            L7d:
                java.util.ArrayList r5 = new java.util.ArrayList
                r5.<init>()
                java.util.Iterator r2 = r2.iterator()
            L86:
                boolean r7 = r2.hasNext()
                if (r7 == 0) goto Lab
                java.lang.Object r7 = r2.next()
                r8 = r7
                com.jbzd.media.movecartoons.bean.response.GroupBean r8 = (com.jbzd.media.movecartoons.bean.response.GroupBean) r8
                int r8 = r8.getLevel()
                r9 = 2
                if (r8 != r9) goto L9c
                r8 = 1
                goto L9d
            L9c:
                r8 = 0
            L9d:
                java.lang.Boolean r8 = kotlin.coroutines.jvm.internal.Boxing.boxBoolean(r8)
                boolean r8 = r8.booleanValue()
                if (r8 == 0) goto L86
                r5.add(r7)
                goto L86
            Lab:
                if (r5 != 0) goto Lb1
                java.util.List r5 = kotlin.collections.CollectionsKt__CollectionsKt.emptyList()
            Lb1:
                b.a.a.a.o.c r2 = new b.a.a.a.o.c
                java.lang.String r11 = r11.getTips()
                java.lang.String r4 = "it.tips"
                kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r11, r4)
                r2.<init>(r6, r5, r11)
                r0.f481e = r3
                java.lang.Object r11 = r12.emit(r2, r0)
                if (r11 != r1) goto Lc8
                return r1
            Lc8:
                kotlin.Unit r11 = kotlin.Unit.INSTANCE
                return r11
            */
            throw new UnsupportedOperationException("Method not decompiled: p005b.p006a.p007a.p008a.p017r.p021n.C0946c.a.emit(java.lang.Object, kotlin.coroutines.Continuation):java.lang.Object");
        }
    }

    public C0946c(InterfaceC3006b interfaceC3006b) {
        this.f478a = interfaceC3006b;
    }

    @Override // p379c.p380a.p383b2.InterfaceC3006b
    @Nullable
    /* renamed from: a */
    public Object mo289a(@NotNull InterfaceC3007c<? super C0909c> interfaceC3007c, @NotNull Continuation continuation) {
        Object mo289a = this.f478a.mo289a(new a(interfaceC3007c, this), continuation);
        return mo289a == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED() ? mo289a : Unit.INSTANCE;
    }
}

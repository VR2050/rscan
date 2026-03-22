package p005b.p006a.p007a.p008a.p017r.p021n;

import com.jbzd.media.movecartoons.bean.response.ChatMsgBean;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import kotlin.coroutines.jvm.internal.ContinuationImpl;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p379c.p380a.p383b2.InterfaceC3006b;
import p379c.p380a.p383b2.InterfaceC3007c;

/* renamed from: b.a.a.a.r.n.b */
/* loaded from: classes2.dex */
public final class C0945b implements InterfaceC3006b<ChatMsgBean> {

    /* renamed from: a */
    public final /* synthetic */ InterfaceC3006b f473a;

    /* renamed from: b.a.a.a.r.n.b$a */
    public static final class a implements InterfaceC3007c<ChatMsgBean> {

        /* renamed from: c */
        public final /* synthetic */ InterfaceC3007c f474c;

        @DebugMetadata(m5319c = "com.jbzd.media.movecartoons.net.repository.ComicsRepository$chatMessageList$$inlined$map$1$2", m5320f = "ComicsRepository.kt", m5321i = {}, m5322l = {140}, m5323m = "emit", m5324n = {}, m5325s = {})
        /* renamed from: b.a.a.a.r.n.b$a$a, reason: collision with other inner class name */
        public static final class C5101a extends ContinuationImpl {

            /* renamed from: c */
            public /* synthetic */ Object f475c;

            /* renamed from: e */
            public int f476e;

            public C5101a(Continuation continuation) {
                super(continuation);
            }

            @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
            @Nullable
            public final Object invokeSuspend(@NotNull Object obj) {
                this.f475c = obj;
                this.f476e |= Integer.MIN_VALUE;
                return a.this.emit(null, this);
            }
        }

        public a(InterfaceC3007c interfaceC3007c, C0945b c0945b) {
            this.f474c = interfaceC3007c;
        }

        /* JADX WARN: Removed duplicated region for block: B:15:0x0031  */
        /* JADX WARN: Removed duplicated region for block: B:8:0x0023  */
        @Override // p379c.p380a.p383b2.InterfaceC3007c
        @org.jetbrains.annotations.Nullable
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public java.lang.Object emit(com.jbzd.media.movecartoons.bean.response.ChatMsgBean r6, @org.jetbrains.annotations.NotNull kotlin.coroutines.Continuation r7) {
            /*
                r5 = this;
                boolean r0 = r7 instanceof p005b.p006a.p007a.p008a.p017r.p021n.C0945b.a.C5101a
                if (r0 == 0) goto L13
                r0 = r7
                b.a.a.a.r.n.b$a$a r0 = (p005b.p006a.p007a.p008a.p017r.p021n.C0945b.a.C5101a) r0
                int r1 = r0.f476e
                r2 = -2147483648(0xffffffff80000000, float:-0.0)
                r3 = r1 & r2
                if (r3 == 0) goto L13
                int r1 = r1 - r2
                r0.f476e = r1
                goto L18
            L13:
                b.a.a.a.r.n.b$a$a r0 = new b.a.a.a.r.n.b$a$a
                r0.<init>(r7)
            L18:
                java.lang.Object r7 = r0.f475c
                java.lang.Object r1 = kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()
                int r2 = r0.f476e
                r3 = 1
                if (r2 == 0) goto L31
                if (r2 != r3) goto L29
                kotlin.ResultKt.throwOnFailure(r7)
                goto L54
            L29:
                java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
                java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
                r6.<init>(r7)
                throw r6
            L31:
                kotlin.ResultKt.throwOnFailure(r7)
                c.a.b2.c r7 = r5.f474c
                com.jbzd.media.movecartoons.bean.response.ChatMsgBean r6 = (com.jbzd.media.movecartoons.bean.response.ChatMsgBean) r6
                com.jbzd.media.movecartoons.bean.response.FaqBean r2 = new com.jbzd.media.movecartoons.bean.response.FaqBean
                r2.<init>()
                java.lang.String r4 = r6.getSystem_head_img()
                r2.system_head_img = r4
                java.util.List r4 = r6.getFaq()
                r2.faq_items = r4
                r6.faqBean = r2
                r0.f476e = r3
                java.lang.Object r6 = r7.emit(r6, r0)
                if (r6 != r1) goto L54
                return r1
            L54:
                kotlin.Unit r6 = kotlin.Unit.INSTANCE
                return r6
            */
            throw new UnsupportedOperationException("Method not decompiled: p005b.p006a.p007a.p008a.p017r.p021n.C0945b.a.emit(java.lang.Object, kotlin.coroutines.Continuation):java.lang.Object");
        }
    }

    public C0945b(InterfaceC3006b interfaceC3006b) {
        this.f473a = interfaceC3006b;
    }

    @Override // p379c.p380a.p383b2.InterfaceC3006b
    @Nullable
    /* renamed from: a */
    public Object mo289a(@NotNull InterfaceC3007c<? super ChatMsgBean> interfaceC3007c, @NotNull Continuation continuation) {
        Object mo289a = this.f473a.mo289a(new a(interfaceC3007c, this), continuation);
        return mo289a == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED() ? mo289a : Unit.INSTANCE;
    }
}

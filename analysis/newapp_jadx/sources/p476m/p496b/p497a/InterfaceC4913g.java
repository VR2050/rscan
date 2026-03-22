package p476m.p496b.p497a;

import java.util.logging.Level;
import kotlin.Result;
import kotlin.ResultKt;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsJvmKt;
import kotlin.coroutines.jvm.internal.ContinuationImpl;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* renamed from: m.b.a.g */
/* loaded from: classes3.dex */
public interface InterfaceC4913g {

    /* renamed from: m.b.a.g$a */
    public static class a {

        /* renamed from: m.b.a.g$a$a, reason: collision with other inner class name */
        public static final class RunnableC5139a implements Runnable {

            /* renamed from: c */
            public final /* synthetic */ Continuation f12537c;

            /* renamed from: e */
            public final /* synthetic */ Exception f12538e;

            public RunnableC5139a(Continuation continuation, Exception exc) {
                this.f12537c = continuation;
                this.f12538e = exc;
            }

            @Override // java.lang.Runnable
            public final void run() {
                Continuation intercepted = IntrinsicsKt__IntrinsicsJvmKt.intercepted(this.f12537c);
                Exception exc = this.f12538e;
                Result.Companion companion = Result.INSTANCE;
                intercepted.resumeWith(Result.m6055constructorimpl(ResultKt.createFailure(exc)));
            }
        }

        @DebugMetadata(m5319c = "retrofit2.KotlinExtensions", m5320f = "KotlinExtensions.kt", m5321i = {0}, m5322l = {113}, m5323m = "suspendAndThrow", m5324n = {"$this$suspendAndThrow"}, m5325s = {"L$0"})
        /* renamed from: m.b.a.g$a$b */
        public static final class b extends ContinuationImpl {

            /* renamed from: c */
            public /* synthetic */ Object f12539c;

            /* renamed from: e */
            public int f12540e;

            /* renamed from: f */
            public Object f12541f;

            public b(Continuation continuation) {
                super(continuation);
            }

            @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
            @Nullable
            public final Object invokeSuspend(@NotNull Object obj) {
                this.f12539c = obj;
                this.f12540e |= Integer.MIN_VALUE;
                return a.m5583a(null, this);
            }
        }

        /* JADX WARN: Removed duplicated region for block: B:15:0x0035  */
        /* JADX WARN: Removed duplicated region for block: B:8:0x0023  */
        @org.jetbrains.annotations.Nullable
        /* renamed from: a */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public static final java.lang.Object m5583a(@org.jetbrains.annotations.NotNull java.lang.Exception r4, @org.jetbrains.annotations.NotNull kotlin.coroutines.Continuation<?> r5) {
            /*
                boolean r0 = r5 instanceof p476m.p496b.p497a.InterfaceC4913g.a.b
                if (r0 == 0) goto L13
                r0 = r5
                m.b.a.g$a$b r0 = (p476m.p496b.p497a.InterfaceC4913g.a.b) r0
                int r1 = r0.f12540e
                r2 = -2147483648(0xffffffff80000000, float:-0.0)
                r3 = r1 & r2
                if (r3 == 0) goto L13
                int r1 = r1 - r2
                r0.f12540e = r1
                goto L18
            L13:
                m.b.a.g$a$b r0 = new m.b.a.g$a$b
                r0.<init>(r5)
            L18:
                java.lang.Object r5 = r0.f12539c
                java.lang.Object r1 = kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()
                int r2 = r0.f12540e
                r3 = 1
                if (r2 == 0) goto L35
                if (r2 != r3) goto L2d
                java.lang.Object r4 = r0.f12541f
                java.lang.Exception r4 = (java.lang.Exception) r4
                kotlin.ResultKt.throwOnFailure(r5)
                goto L5a
            L2d:
                java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
                java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
                r4.<init>(r5)
                throw r4
            L35:
                kotlin.ResultKt.throwOnFailure(r5)
                r0.f12541f = r4
                r0.f12540e = r3
                c.a.c0 r5 = p379c.p380a.C3079m0.f8430a
                kotlin.coroutines.CoroutineContext r2 = r0.get$context()
                m.b.a.g$a$a r3 = new m.b.a.g$a$a
                r3.<init>(r0, r4)
                r5.dispatch(r2, r3)
                java.lang.Object r4 = kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()
                java.lang.Object r5 = kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()
                if (r4 != r5) goto L57
                kotlin.coroutines.jvm.internal.DebugProbesKt.probeCoroutineSuspended(r0)
            L57:
                if (r4 != r1) goto L5a
                return r1
            L5a:
                kotlin.Unit r4 = kotlin.Unit.INSTANCE
                return r4
            */
            throw new UnsupportedOperationException("Method not decompiled: p476m.p496b.p497a.InterfaceC4913g.a.m5583a(java.lang.Exception, kotlin.coroutines.Continuation):java.lang.Object");
        }
    }

    /* renamed from: m.b.a.g$b */
    public static class b implements InterfaceC4913g {
        @Override // p476m.p496b.p497a.InterfaceC4913g
        /* renamed from: a */
        public void mo5581a(Level level, String str) {
            System.out.println("[" + level + "] " + str);
        }

        @Override // p476m.p496b.p497a.InterfaceC4913g
        /* renamed from: b */
        public void mo5582b(Level level, String str, Throwable th) {
            System.out.println("[" + level + "] " + str);
            th.printStackTrace(System.out);
        }
    }

    /* renamed from: a */
    void mo5581a(Level level, String str);

    /* renamed from: b */
    void mo5582b(Level level, String str, Throwable th);
}

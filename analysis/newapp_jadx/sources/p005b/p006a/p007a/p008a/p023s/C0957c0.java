package p005b.p006a.p007a.p008a.p023s;

import com.jbzd.media.movecartoons.bean.event.EventMusic;
import com.jbzd.media.movecartoons.service.AudioPlayerService;
import kotlin.ResultKt;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import kotlin.coroutines.jvm.internal.Boxing;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.coroutines.jvm.internal.SuspendLambda;
import kotlin.jvm.functions.Function2;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.InterfaceC3055e0;
import p476m.p496b.p497a.C4909c;

@DebugMetadata(m5319c = "com.jbzd.media.movecartoons.service.AudioPlayerService$updatePosition$1", m5320f = "AudioPlayerService.kt", m5321i = {}, m5322l = {455}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
/* renamed from: b.a.a.a.s.c0 */
/* loaded from: classes2.dex */
public final class C0957c0 extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {

    /* renamed from: c */
    public int f566c;

    /* renamed from: e */
    public final /* synthetic */ AudioPlayerService f567e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0957c0(AudioPlayerService audioPlayerService, Continuation<? super C0957c0> continuation) {
        super(2, continuation);
        this.f567e = audioPlayerService;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @NotNull
    public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
        return new C0957c0(this.f567e, continuation);
    }

    @Override // kotlin.jvm.functions.Function2
    public Object invoke(InterfaceC3055e0 interfaceC3055e0, Continuation<? super Unit> continuation) {
        return new C0957c0(this.f567e, continuation).invokeSuspend(Unit.INSTANCE);
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @Nullable
    public final Object invokeSuspend(@NotNull Object obj) {
        Object coroutine_suspended = IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
        int i2 = this.f566c;
        if (i2 == 0) {
            ResultKt.throwOnFailure(obj);
        } else {
            if (i2 != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            try {
                ResultKt.throwOnFailure(obj);
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
        while (this.f567e.mediaPlayer.isPlaying()) {
            AudioPlayerService audioPlayerService = this.f567e;
            audioPlayerService.currentPosition.setValue(Boxing.boxInt(audioPlayerService.mediaPlayer.getCurrentPosition()));
            C4909c.m5569b().m5574g(new EventMusic("pos", this.f567e.currentPosition.getValue(), null, 4, null));
            this.f566c = 1;
            if (C2354n.m2422Q(300L, this) == coroutine_suspended) {
                return coroutine_suspended;
            }
        }
        return Unit.INSTANCE;
    }
}

package com.jbzd.media.movecartoons.p396ui.novel;

import android.graphics.Bitmap;
import com.jbzd.media.movecartoons.bean.response.novel.NovelChapter;
import com.jbzd.media.movecartoons.bean.response.novel.NovelChapterInfoBean;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.ResultKt;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.coroutines.jvm.internal.SuspendLambda;
import kotlin.jvm.functions.Function2;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p143g.p144a.p166q.C1777d;
import p005b.p143g.p144a.p170s.C1802d;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p336c.C2851b;
import p379c.p380a.AbstractC3077l1;
import p379c.p380a.C3079m0;
import p379c.p380a.InterfaceC3055e0;
import p379c.p380a.p381a.C2964m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\u0010\u0002\u001a\u00020\u0001*\u00020\u0000H\u008a@¢\u0006\u0004\b\u0002\u0010\u0003"}, m5311d2 = {"Lc/a/e0;", "", "<anonymous>", "(Lc/a/e0;)V"}, m5312k = 3, m5313mv = {1, 5, 1})
@DebugMetadata(m5319c = "com.jbzd.media.movecartoons.ui.novel.AudioPlayerActivity$bindEvent$3$1$1$1", m5320f = "AudioPlayerActivity.kt", m5321i = {}, m5322l = {132}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
/* loaded from: classes2.dex */
public final class AudioPlayerActivity$bindEvent$3$1$1$1 extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {
    public final /* synthetic */ NovelChapterInfoBean $it;
    public final /* synthetic */ AudioPlayerActivity $it1;
    public final /* synthetic */ AudioPlayerViewModel $this_apply;
    public int label;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\u0010\u0002\u001a\u00020\u0001*\u00020\u0000H\u008a@¢\u0006\u0004\b\u0002\u0010\u0003"}, m5311d2 = {"Lc/a/e0;", "", "<anonymous>", "(Lc/a/e0;)V"}, m5312k = 3, m5313mv = {1, 5, 1})
    @DebugMetadata(m5319c = "com.jbzd.media.movecartoons.ui.novel.AudioPlayerActivity$bindEvent$3$1$1$1$1", m5320f = "AudioPlayerActivity.kt", m5321i = {}, m5322l = {}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
    /* renamed from: com.jbzd.media.movecartoons.ui.novel.AudioPlayerActivity$bindEvent$3$1$1$1$1 */
    public static final class C38311 extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {
        public final /* synthetic */ Bitmap $coverBitmap;
        public final /* synthetic */ AudioPlayerViewModel $this_apply;
        public int label;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C38311(AudioPlayerViewModel audioPlayerViewModel, Bitmap bitmap, Continuation<? super C38311> continuation) {
            super(2, continuation);
            this.$this_apply = audioPlayerViewModel;
            this.$coverBitmap = bitmap;
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @NotNull
        public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
            return new C38311(this.$this_apply, this.$coverBitmap, continuation);
        }

        @Override // kotlin.jvm.functions.Function2
        @Nullable
        public final Object invoke(@NotNull InterfaceC3055e0 interfaceC3055e0, @Nullable Continuation<? super Unit> continuation) {
            return ((C38311) create(interfaceC3055e0, continuation)).invokeSuspend(Unit.INSTANCE);
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
            if (this.label != 0) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            ResultKt.throwOnFailure(obj);
            Objects.requireNonNull(this.$this_apply.getService());
            return Unit.INSTANCE;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public AudioPlayerActivity$bindEvent$3$1$1$1(AudioPlayerActivity audioPlayerActivity, NovelChapterInfoBean novelChapterInfoBean, AudioPlayerViewModel audioPlayerViewModel, Continuation<? super AudioPlayerActivity$bindEvent$3$1$1$1> continuation) {
        super(2, continuation);
        this.$it1 = audioPlayerActivity;
        this.$it = novelChapterInfoBean;
        this.$this_apply = audioPlayerViewModel;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @NotNull
    public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
        return new AudioPlayerActivity$bindEvent$3$1$1$1(this.$it1, this.$it, this.$this_apply, continuation);
    }

    @Override // kotlin.jvm.functions.Function2
    @Nullable
    public final Object invoke(@NotNull InterfaceC3055e0 interfaceC3055e0, @Nullable Continuation<? super Unit> continuation) {
        return ((AudioPlayerActivity$bindEvent$3$1$1$1) create(interfaceC3055e0, continuation)).invokeSuspend(Unit.INSTANCE);
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @Nullable
    public final Object invokeSuspend(@NotNull Object obj) {
        String str;
        Object coroutine_suspended = IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
        int i2 = this.label;
        if (i2 == 0) {
            ResultKt.throwOnFailure(obj);
            C2851b<Bitmap> mo769b = C2354n.m2467d2(this.$it1).mo769b();
            NovelChapter novelChapter = this.$it.chapter;
            if (novelChapter == null || (str = novelChapter.img) == null) {
                str = "";
            }
            mo769b.f1865I = str;
            mo769b.f1868L = true;
            C1777d c1777d = new C1777d(Integer.MIN_VALUE, Integer.MIN_VALUE);
            mo769b.m756Q(c1777d, c1777d, mo769b, C1802d.f2756b);
            Bitmap bitmap = (Bitmap) c1777d.get();
            C3079m0 c3079m0 = C3079m0.f8432c;
            AbstractC3077l1 abstractC3077l1 = C2964m.f8127b;
            C38311 c38311 = new C38311(this.$this_apply, bitmap, null);
            this.label = 1;
            if (C2354n.m2471e2(abstractC3077l1, c38311, this) == coroutine_suspended) {
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

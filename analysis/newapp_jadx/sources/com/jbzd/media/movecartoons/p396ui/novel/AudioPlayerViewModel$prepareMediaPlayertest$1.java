package com.jbzd.media.movecartoons.p396ui.novel;

import android.media.MediaPlayer;
import androidx.lifecycle.MutableLiveData;
import com.jbzd.media.movecartoons.bean.event.EventMusic;
import com.jbzd.media.movecartoons.p396ui.novel.AudioPlayerViewModel;
import com.jbzd.media.movecartoons.p396ui.novel.AudioPlayerViewModel$prepareMediaPlayertest$1;
import com.jbzd.media.movecartoons.service.AudioPlayerService;
import java.io.IOException;
import java.util.Arrays;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.ResultKt;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import kotlin.coroutines.jvm.internal.Boxing;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.coroutines.jvm.internal.SuspendLambda;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.StringCompanionObject;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.C2827a;
import p005b.p327w.p330b.p331b.ApplicationC2828a;
import p379c.p380a.AbstractC3077l1;
import p379c.p380a.C3079m0;
import p379c.p380a.InterfaceC3055e0;
import p379c.p380a.p381a.C2964m;
import p476m.p496b.p497a.C4909c;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\u0010\u0002\u001a\u00020\u0001*\u00020\u0000H\u008a@¢\u0006\u0004\b\u0002\u0010\u0003"}, m5311d2 = {"Lc/a/e0;", "", "<anonymous>", "(Lc/a/e0;)V"}, m5312k = 3, m5313mv = {1, 5, 1})
@DebugMetadata(m5319c = "com.jbzd.media.movecartoons.ui.novel.AudioPlayerViewModel$prepareMediaPlayertest$1", m5320f = "AudioPlayerViewModel.kt", m5321i = {}, m5322l = {188}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
/* loaded from: classes2.dex */
public final class AudioPlayerViewModel$prepareMediaPlayertest$1 extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {
    public final /* synthetic */ Function0<Unit> $onCompletion;
    public final /* synthetic */ Function0<Unit> $onMediaPlayerReady;
    public final /* synthetic */ String $url;
    public int label;
    public final /* synthetic */ AudioPlayerViewModel this$0;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\u0010\u0002\u001a\u00020\u0001*\u00020\u0000H\u008a@¢\u0006\u0004\b\u0002\u0010\u0003"}, m5311d2 = {"Lc/a/e0;", "", "<anonymous>", "(Lc/a/e0;)V"}, m5312k = 3, m5313mv = {1, 5, 1})
    @DebugMetadata(m5319c = "com.jbzd.media.movecartoons.ui.novel.AudioPlayerViewModel$prepareMediaPlayertest$1$1", m5320f = "AudioPlayerViewModel.kt", m5321i = {}, m5322l = {}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
    /* renamed from: com.jbzd.media.movecartoons.ui.novel.AudioPlayerViewModel$prepareMediaPlayertest$1$1 */
    public static final class C38331 extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {
        public final /* synthetic */ Function0<Unit> $onCompletion;
        public final /* synthetic */ Function0<Unit> $onMediaPlayerReady;
        public final /* synthetic */ String $url;
        public int label;
        public final /* synthetic */ AudioPlayerViewModel this$0;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C38331(String str, AudioPlayerViewModel audioPlayerViewModel, Function0<Unit> function0, Function0<Unit> function02, Continuation<? super C38331> continuation) {
            super(2, continuation);
            this.$url = str;
            this.this$0 = audioPlayerViewModel;
            this.$onMediaPlayerReady = function0;
            this.$onCompletion = function02;
        }

        /* JADX INFO: Access modifiers changed from: private */
        /* renamed from: invokeSuspend$lambda-0, reason: not valid java name */
        public static final void m5907invokeSuspend$lambda0(AudioPlayerViewModel audioPlayerViewModel, MediaPlayer mediaPlayer) {
            audioPlayerViewModel.getService().currentPosition.setValue(0);
            audioPlayerViewModel.getService().m4220v(false);
            C4909c.m5569b().m5574g(new EventMusic("harmony", null, null, 6, null));
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @NotNull
        public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
            return new C38331(this.$url, this.this$0, this.$onMediaPlayerReady, this.$onCompletion, continuation);
        }

        @Override // kotlin.jvm.functions.Function2
        @Nullable
        public final Object invoke(@NotNull InterfaceC3055e0 interfaceC3055e0, @Nullable Continuation<? super Unit> continuation) {
            return ((C38331) create(interfaceC3055e0, continuation)).invokeSuspend(Unit.INSTANCE);
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
            if (this.label != 0) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            ResultKt.throwOnFailure(obj);
            if (Intrinsics.areEqual(this.$url, "")) {
                this.this$0.getService().currentPosition.setValue(Boxing.boxInt(this.this$0.getService().mediaPlayer.getCurrentPosition()));
                MutableLiveData<String> mutableLiveData = this.this$0.getService().endTime;
                int duration = this.this$0.getService().mediaPlayer.getDuration() / 1000;
                StringCompanionObject stringCompanionObject = StringCompanionObject.INSTANCE;
                String format = String.format("%02d:%02d", Arrays.copyOf(new Object[]{Integer.valueOf(duration / 60), Integer.valueOf(duration % 60)}, 2));
                Intrinsics.checkNotNullExpressionValue(format, "format(format, *args)");
                mutableLiveData.setValue(format);
                MediaPlayer mediaPlayer = this.this$0.getService().mediaPlayer;
                final AudioPlayerViewModel audioPlayerViewModel = this.this$0;
                mediaPlayer.setOnCompletionListener(new MediaPlayer.OnCompletionListener() { // from class: b.a.a.a.t.j.c
                    @Override // android.media.MediaPlayer.OnCompletionListener
                    public final void onCompletion(MediaPlayer mediaPlayer2) {
                        AudioPlayerViewModel$prepareMediaPlayertest$1.C38331.m5907invokeSuspend$lambda0(AudioPlayerViewModel.this, mediaPlayer2);
                    }
                });
                this.$onMediaPlayerReady.invoke();
            } else {
                this.this$0.getLoadingProgressBar().setValue(Boxing.boxBoolean(true));
                final AudioPlayerService service = this.this$0.getService();
                String url = this.$url;
                final AudioPlayerViewModel audioPlayerViewModel2 = this.this$0;
                final Function0<Unit> function0 = this.$onMediaPlayerReady;
                final Function0<Unit> onPreparedListener = new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.AudioPlayerViewModel.prepareMediaPlayertest.1.1.2
                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                    {
                        super(0);
                    }

                    @Override // kotlin.jvm.functions.Function0
                    public /* bridge */ /* synthetic */ Unit invoke() {
                        invoke2();
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2() {
                        MutableLiveData<String> mutableLiveData2 = AudioPlayerViewModel.this.getService().endTime;
                        int duration2 = AudioPlayerViewModel.this.getService().mediaPlayer.getDuration() / 1000;
                        StringCompanionObject stringCompanionObject2 = StringCompanionObject.INSTANCE;
                        String format2 = String.format("%02d:%02d", Arrays.copyOf(new Object[]{Integer.valueOf(duration2 / 60), Integer.valueOf(duration2 % 60)}, 2));
                        Intrinsics.checkNotNullExpressionValue(format2, "format(format, *args)");
                        mutableLiveData2.setValue(format2);
                        function0.invoke();
                    }
                };
                final Function0<Unit> function02 = this.$onCompletion;
                final Function0<Unit> onCompletionListener = new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.AudioPlayerViewModel.prepareMediaPlayertest.1.1.3
                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                    {
                        super(0);
                    }

                    @Override // kotlin.jvm.functions.Function0
                    public /* bridge */ /* synthetic */ Unit invoke() {
                        invoke2();
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2() {
                        function02.invoke();
                    }
                };
                Objects.requireNonNull(service);
                Intrinsics.checkNotNullParameter(url, "url");
                Intrinsics.checkNotNullParameter(onPreparedListener, "onPreparedListener");
                Intrinsics.checkNotNullParameter(onCompletionListener, "onCompletionListener");
                try {
                    service.mediaPlayer.reset();
                    service.mediaPlayer.setDataSource(url);
                    service.mediaPlayer.prepareAsync();
                    service.mediaPlayer.setOnPreparedListener(new MediaPlayer.OnPreparedListener() { // from class: b.a.a.a.s.d
                        @Override // android.media.MediaPlayer.OnPreparedListener
                        public final void onPrepared(MediaPlayer mediaPlayer2) {
                            AudioPlayerService this$0 = AudioPlayerService.this;
                            Function0 onPreparedListener2 = onPreparedListener;
                            int i2 = AudioPlayerService.f10064e;
                            Intrinsics.checkNotNullParameter(this$0, "this$0");
                            Intrinsics.checkNotNullParameter(onPreparedListener2, "$onPreparedListener");
                            this$0.currentPosition.setValue(0);
                            MutableLiveData<String> mutableLiveData2 = this$0.endTime;
                            int duration2 = this$0.mediaPlayer.getDuration() / 1000;
                            StringCompanionObject stringCompanionObject2 = StringCompanionObject.INSTANCE;
                            String format2 = String.format("%02d:%02d", Arrays.copyOf(new Object[]{Integer.valueOf(duration2 / 60), Integer.valueOf(duration2 % 60)}, 2));
                            Intrinsics.checkNotNullExpressionValue(format2, "format(format, *args)");
                            mutableLiveData2.setValue(format2);
                            this$0.m4200b();
                            onPreparedListener2.invoke();
                        }
                    });
                    service.mediaPlayer.setOnCompletionListener(new MediaPlayer.OnCompletionListener() { // from class: b.a.a.a.s.c
                        @Override // android.media.MediaPlayer.OnCompletionListener
                        public final void onCompletion(MediaPlayer mediaPlayer2) {
                            AudioPlayerService this$0 = AudioPlayerService.this;
                            Function0 onCompletionListener2 = onCompletionListener;
                            int i2 = AudioPlayerService.f10064e;
                            Intrinsics.checkNotNullParameter(this$0, "this$0");
                            Intrinsics.checkNotNullParameter(onCompletionListener2, "$onCompletionListener");
                            ApplicationC2828a applicationC2828a = C2827a.f7670a;
                            if (applicationC2828a == null) {
                                Intrinsics.throwUninitializedPropertyAccessException("context");
                                throw null;
                            }
                            if (C2354n.m2411M0(applicationC2828a)) {
                                this$0.m4220v(false);
                                this$0.currentPosition.setValue(0);
                                C4909c.m5569b().m5574g(new EventMusic("harmony", null, null, 6, null));
                                onCompletionListener2.invoke();
                                this$0.m4208j(new C0981z(this$0), C0953a0.f561c, C0955b0.f563c);
                            }
                        }
                    });
                    service.mediaPlayer.setOnErrorListener(new MediaPlayer.OnErrorListener() { // from class: b.a.a.a.s.b
                        @Override // android.media.MediaPlayer.OnErrorListener
                        public final boolean onError(MediaPlayer mediaPlayer2, int i2, int i3) {
                            int i4 = AudioPlayerService.f10064e;
                            C4909c.m5569b().m5574g(new EventMusic("setOnErrorListener", null, null, 6, null));
                            return true;
                        }
                    });
                } catch (IOException e2) {
                    e2.printStackTrace();
                }
            }
            return Unit.INSTANCE;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public AudioPlayerViewModel$prepareMediaPlayertest$1(String str, AudioPlayerViewModel audioPlayerViewModel, Function0<Unit> function0, Function0<Unit> function02, Continuation<? super AudioPlayerViewModel$prepareMediaPlayertest$1> continuation) {
        super(2, continuation);
        this.$url = str;
        this.this$0 = audioPlayerViewModel;
        this.$onMediaPlayerReady = function0;
        this.$onCompletion = function02;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @NotNull
    public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
        return new AudioPlayerViewModel$prepareMediaPlayertest$1(this.$url, this.this$0, this.$onMediaPlayerReady, this.$onCompletion, continuation);
    }

    @Override // kotlin.jvm.functions.Function2
    @Nullable
    public final Object invoke(@NotNull InterfaceC3055e0 interfaceC3055e0, @Nullable Continuation<? super Unit> continuation) {
        return ((AudioPlayerViewModel$prepareMediaPlayertest$1) create(interfaceC3055e0, continuation)).invokeSuspend(Unit.INSTANCE);
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @Nullable
    public final Object invokeSuspend(@NotNull Object obj) {
        Object coroutine_suspended = IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
        int i2 = this.label;
        try {
            if (i2 == 0) {
                ResultKt.throwOnFailure(obj);
                C3079m0 c3079m0 = C3079m0.f8432c;
                AbstractC3077l1 abstractC3077l1 = C2964m.f8127b;
                C38331 c38331 = new C38331(this.$url, this.this$0, this.$onMediaPlayerReady, this.$onCompletion, null);
                this.label = 1;
                if (C2354n.m2471e2(abstractC3077l1, c38331, this) == coroutine_suspended) {
                    return coroutine_suspended;
                }
            } else {
                if (i2 != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                ResultKt.throwOnFailure(obj);
            }
        } catch (IOException e2) {
            e2.printStackTrace();
        }
        return Unit.INSTANCE;
    }
}

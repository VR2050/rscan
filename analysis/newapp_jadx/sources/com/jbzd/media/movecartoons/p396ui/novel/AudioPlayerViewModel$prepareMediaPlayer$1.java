package com.jbzd.media.movecartoons.p396ui.novel;

import android.media.MediaPlayer;
import android.widget.SeekBar;
import androidx.lifecycle.MutableLiveData;
import com.jbzd.media.movecartoons.bean.event.EventMusic;
import com.jbzd.media.movecartoons.bean.response.novel.NovelChapterInfoBean;
import com.jbzd.media.movecartoons.p396ui.novel.AudioPlayerViewModel$prepareMediaPlayer$1;
import com.jbzd.media.movecartoons.service.AudioPlayerService;
import java.io.IOException;
import java.util.Arrays;
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
import p379c.p380a.AbstractC3077l1;
import p379c.p380a.C3079m0;
import p379c.p380a.InterfaceC3055e0;
import p379c.p380a.p381a.C2964m;
import p476m.p496b.p497a.C4909c;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\u0010\u0002\u001a\u00020\u0001*\u00020\u0000H\u008a@¢\u0006\u0004\b\u0002\u0010\u0003"}, m5311d2 = {"Lc/a/e0;", "", "<anonymous>", "(Lc/a/e0;)V"}, m5312k = 3, m5313mv = {1, 5, 1})
@DebugMetadata(m5319c = "com.jbzd.media.movecartoons.ui.novel.AudioPlayerViewModel$prepareMediaPlayer$1", m5320f = "AudioPlayerViewModel.kt", m5321i = {}, m5322l = {242}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
/* loaded from: classes2.dex */
public final class AudioPlayerViewModel$prepareMediaPlayer$1 extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {
    public final /* synthetic */ NovelChapterInfoBean $item;
    public final /* synthetic */ Function0<Unit> $onCompletion;
    public final /* synthetic */ Function0<Unit> $onMediaPlayerReady;
    public final /* synthetic */ SeekBar $seekBar;
    public final /* synthetic */ String $url;
    public int label;
    public final /* synthetic */ AudioPlayerViewModel this$0;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\u0010\u0002\u001a\u00020\u0001*\u00020\u0000H\u008a@¢\u0006\u0004\b\u0002\u0010\u0003"}, m5311d2 = {"Lc/a/e0;", "", "<anonymous>", "(Lc/a/e0;)V"}, m5312k = 3, m5313mv = {1, 5, 1})
    @DebugMetadata(m5319c = "com.jbzd.media.movecartoons.ui.novel.AudioPlayerViewModel$prepareMediaPlayer$1$1", m5320f = "AudioPlayerViewModel.kt", m5321i = {}, m5322l = {}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
    /* renamed from: com.jbzd.media.movecartoons.ui.novel.AudioPlayerViewModel$prepareMediaPlayer$1$1 */
    public static final class C38321 extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {
        public final /* synthetic */ NovelChapterInfoBean $item;
        public final /* synthetic */ Function0<Unit> $onCompletion;
        public final /* synthetic */ Function0<Unit> $onMediaPlayerReady;
        public final /* synthetic */ SeekBar $seekBar;
        public final /* synthetic */ String $url;
        public int label;
        public final /* synthetic */ AudioPlayerViewModel this$0;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C38321(String str, SeekBar seekBar, AudioPlayerViewModel audioPlayerViewModel, Function0<Unit> function0, NovelChapterInfoBean novelChapterInfoBean, Function0<Unit> function02, Continuation<? super C38321> continuation) {
            super(2, continuation);
            this.$url = str;
            this.$seekBar = seekBar;
            this.this$0 = audioPlayerViewModel;
            this.$onMediaPlayerReady = function0;
            this.$item = novelChapterInfoBean;
            this.$onCompletion = function02;
        }

        /* JADX INFO: Access modifiers changed from: private */
        /* renamed from: invokeSuspend$lambda-0, reason: not valid java name */
        public static final void m5906invokeSuspend$lambda0(SeekBar seekBar, AudioPlayerViewModel audioPlayerViewModel, MediaPlayer mediaPlayer) {
            seekBar.setMax(0);
            audioPlayerViewModel.getService().currentPosition.setValue(0);
            audioPlayerViewModel.getService().m4220v(false);
            C4909c.m5569b().m5574g(new EventMusic("harmony", null, null, 6, null));
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @NotNull
        public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
            return new C38321(this.$url, this.$seekBar, this.this$0, this.$onMediaPlayerReady, this.$item, this.$onCompletion, continuation);
        }

        @Override // kotlin.jvm.functions.Function2
        @Nullable
        public final Object invoke(@NotNull InterfaceC3055e0 interfaceC3055e0, @Nullable Continuation<? super Unit> continuation) {
            return ((C38321) create(interfaceC3055e0, continuation)).invokeSuspend(Unit.INSTANCE);
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
                this.$seekBar.setMax(this.this$0.getService().mediaPlayer.getDuration());
                this.this$0.getService().currentPosition.setValue(Boxing.boxInt(this.this$0.getService().mediaPlayer.getCurrentPosition()));
                MutableLiveData<String> mutableLiveData = this.this$0.getService().endTime;
                int duration = this.this$0.getService().mediaPlayer.getDuration() / 1000;
                StringCompanionObject stringCompanionObject = StringCompanionObject.INSTANCE;
                String format = String.format("%02d:%02d", Arrays.copyOf(new Object[]{Integer.valueOf(duration / 60), Integer.valueOf(duration % 60)}, 2));
                Intrinsics.checkNotNullExpressionValue(format, "format(format, *args)");
                mutableLiveData.setValue(format);
                MediaPlayer mediaPlayer = this.this$0.getService().mediaPlayer;
                final SeekBar seekBar = this.$seekBar;
                final AudioPlayerViewModel audioPlayerViewModel = this.this$0;
                mediaPlayer.setOnCompletionListener(new MediaPlayer.OnCompletionListener() { // from class: b.a.a.a.t.j.b
                    @Override // android.media.MediaPlayer.OnCompletionListener
                    public final void onCompletion(MediaPlayer mediaPlayer2) {
                        AudioPlayerViewModel$prepareMediaPlayer$1.C38321.m5906invokeSuspend$lambda0(seekBar, audioPlayerViewModel, mediaPlayer2);
                    }
                });
                this.$onMediaPlayerReady.invoke();
            } else {
                this.this$0.getLoadingProgressBar().setValue(Boxing.boxBoolean(true));
                AudioPlayerService service = this.this$0.getService();
                NovelChapterInfoBean novelChapterInfoBean = this.$item;
                final SeekBar seekBar2 = this.$seekBar;
                final AudioPlayerViewModel audioPlayerViewModel2 = this.this$0;
                final Function0<Unit> function0 = this.$onMediaPlayerReady;
                Function0<Unit> function02 = new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.AudioPlayerViewModel.prepareMediaPlayer.1.1.2
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
                        seekBar2.setMax(audioPlayerViewModel2.getService().mediaPlayer.getDuration());
                        MutableLiveData<String> mutableLiveData2 = audioPlayerViewModel2.getService().endTime;
                        int duration2 = audioPlayerViewModel2.getService().mediaPlayer.getDuration() / 1000;
                        StringCompanionObject stringCompanionObject2 = StringCompanionObject.INSTANCE;
                        String format2 = String.format("%02d:%02d", Arrays.copyOf(new Object[]{Integer.valueOf(duration2 / 60), Integer.valueOf(duration2 % 60)}, 2));
                        Intrinsics.checkNotNullExpressionValue(format2, "format(format, *args)");
                        mutableLiveData2.setValue(format2);
                        function0.invoke();
                    }
                };
                final SeekBar seekBar3 = this.$seekBar;
                final Function0<Unit> function03 = this.$onCompletion;
                service.m4210l(novelChapterInfoBean, function02, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.AudioPlayerViewModel.prepareMediaPlayer.1.1.3
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
                        seekBar3.setMax(0);
                        function03.invoke();
                    }
                });
            }
            return Unit.INSTANCE;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public AudioPlayerViewModel$prepareMediaPlayer$1(String str, SeekBar seekBar, AudioPlayerViewModel audioPlayerViewModel, Function0<Unit> function0, NovelChapterInfoBean novelChapterInfoBean, Function0<Unit> function02, Continuation<? super AudioPlayerViewModel$prepareMediaPlayer$1> continuation) {
        super(2, continuation);
        this.$url = str;
        this.$seekBar = seekBar;
        this.this$0 = audioPlayerViewModel;
        this.$onMediaPlayerReady = function0;
        this.$item = novelChapterInfoBean;
        this.$onCompletion = function02;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @NotNull
    public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
        return new AudioPlayerViewModel$prepareMediaPlayer$1(this.$url, this.$seekBar, this.this$0, this.$onMediaPlayerReady, this.$item, this.$onCompletion, continuation);
    }

    @Override // kotlin.jvm.functions.Function2
    @Nullable
    public final Object invoke(@NotNull InterfaceC3055e0 interfaceC3055e0, @Nullable Continuation<? super Unit> continuation) {
        return ((AudioPlayerViewModel$prepareMediaPlayer$1) create(interfaceC3055e0, continuation)).invokeSuspend(Unit.INSTANCE);
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
                C38321 c38321 = new C38321(this.$url, this.$seekBar, this.this$0, this.$onMediaPlayerReady, this.$item, this.$onCompletion, null);
                this.label = 1;
                if (C2354n.m2471e2(abstractC3077l1, c38321, this) == coroutine_suspended) {
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

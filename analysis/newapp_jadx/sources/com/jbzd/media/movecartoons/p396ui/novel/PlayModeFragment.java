package com.jbzd.media.movecartoons.p396ui.novel;

import android.animation.ObjectAnimator;
import android.content.Context;
import android.content.res.Resources;
import android.os.Bundle;
import android.view.View;
import android.view.animation.LinearInterpolator;
import android.widget.ImageView;
import android.widget.ProgressBar;
import android.widget.SeekBar;
import android.widget.TextView;
import androidx.annotation.RequiresApi;
import androidx.constraintlayout.motion.widget.Key;
import androidx.core.app.NotificationCompat;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;
import androidx.fragment.app.FragmentViewModelLazyKt;
import androidx.lifecycle.Observer;
import androidx.lifecycle.ViewModelProvider;
import androidx.lifecycle.ViewModelStore;
import com.jbzd.media.movecartoons.bean.event.EventMusic;
import com.jbzd.media.movecartoons.bean.response.VideoTypeBean;
import com.jbzd.media.movecartoons.bean.response.novel.NovelChapter;
import com.jbzd.media.movecartoons.bean.response.novel.NovelChapterInfoBean;
import com.jbzd.media.movecartoons.bean.response.novel.NovelDetailInfoBean;
import com.jbzd.media.movecartoons.core.MyThemeViewModelFragment;
import com.jbzd.media.movecartoons.p396ui.dialog.PostVipDialog;
import com.jbzd.media.movecartoons.p396ui.dialog.SpeedBottomDialog;
import com.jbzd.media.movecartoons.p396ui.dialog.TimingBottomDialog;
import com.jbzd.media.movecartoons.p396ui.index.home.HomeDataHelper;
import com.jbzd.media.movecartoons.p396ui.novel.AudioPlayerViewModel;
import com.jbzd.media.movecartoons.p396ui.novel.NovelTableContentAllActivity;
import com.jbzd.media.movecartoons.p396ui.novel.PlayModeFragment;
import com.jbzd.media.movecartoons.p396ui.share.InviteActivity;
import com.jbzd.media.movecartoons.view.image.CircleImageView;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseFragment;
import com.qunidayede.supportlibrary.widget.MarqueeTextView;
import java.io.Serializable;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import kotlin.text.StringsKt__StringsJVMKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p496b.p497a.C4909c;
import p476m.p496b.p497a.InterfaceC4919m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000|\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u001c\n\u0002\u0010\u000e\n\u0002\b\u000e\n\u0002\u0018\u0002\n\u0002\b\f\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\n\u0018\u0000 \u0084\u00012\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0002\u0084\u0001B\b¢\u0006\u0005\b\u0083\u0001\u0010\u0005J\u000f\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0004\u0010\u0005J\u000f\u0010\u0006\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0006\u0010\u0005J\u000f\u0010\b\u001a\u00020\u0007H\u0016¢\u0006\u0004\b\b\u0010\tJ\u000f\u0010\n\u001a\u00020\u0003H\u0017¢\u0006\u0004\b\n\u0010\u0005J\u000f\u0010\u000b\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u000b\u0010\fJ\u0017\u0010\u000f\u001a\u00020\u00032\u0006\u0010\u000e\u001a\u00020\rH\u0007¢\u0006\u0004\b\u000f\u0010\u0010J\u000f\u0010\u0011\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0011\u0010\u0005R\u001d\u0010\u0017\u001a\u00020\u00128F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0013\u0010\u0014\u001a\u0004\b\u0015\u0010\u0016R\u0018\u0010\u0019\u001a\u0004\u0018\u00010\u00188\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0019\u0010\u001aR\u001d\u0010\u001f\u001a\u00020\u001b8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001c\u0010\u0014\u001a\u0004\b\u001d\u0010\u001eR\u0018\u0010 \u001a\u0004\u0018\u00010\u00188\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b \u0010\u001aR%\u0010&\u001a\n \"*\u0004\u0018\u00010!0!8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b#\u0010\u0014\u001a\u0004\b$\u0010%R\u001d\u0010+\u001a\u00020'8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b(\u0010\u0014\u001a\u0004\b)\u0010*R\u0018\u0010,\u001a\u0004\u0018\u00010\u00188\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b,\u0010\u001aR\u001d\u0010/\u001a\u00020!8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b-\u0010\u0014\u001a\u0004\b.\u0010%R\u0018\u00100\u001a\u0004\u0018\u00010\u00188\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b0\u0010\u001aR\u001d\u00103\u001a\u00020!8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b1\u0010\u0014\u001a\u0004\b2\u0010%R\u001d\u00106\u001a\u00020'8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b4\u0010\u0014\u001a\u0004\b5\u0010*R\u001d\u00109\u001a\u00020'8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b7\u0010\u0014\u001a\u0004\b8\u0010*R\u001d\u0010<\u001a\u00020\u00028F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b:\u0010\u0014\u001a\u0004\b;\u0010\fR%\u0010?\u001a\n \"*\u0004\u0018\u00010!0!8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b=\u0010\u0014\u001a\u0004\b>\u0010%R\u0018\u0010@\u001a\u0004\u0018\u00010\u00188\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b@\u0010\u001aR\u001d\u0010C\u001a\u00020!8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bA\u0010\u0014\u001a\u0004\bB\u0010%R\u001d\u0010H\u001a\u00020D8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bE\u0010\u0014\u001a\u0004\bF\u0010GR\u001d\u0010K\u001a\u00020\u001b8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bI\u0010\u0014\u001a\u0004\bJ\u0010\u001eR\u001d\u0010N\u001a\u00020!8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bL\u0010\u0014\u001a\u0004\bM\u0010%R\u0018\u0010O\u001a\u0004\u0018\u00010\u00188\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\bO\u0010\u001aR\u001d\u0010R\u001a\u00020\u001b8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bP\u0010\u0014\u001a\u0004\bQ\u0010\u001eR\u001d\u0010W\u001a\u00020S8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bT\u0010\u0014\u001a\u0004\bU\u0010VR\u0016\u0010X\u001a\u00020D8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\bX\u0010YR\u001d\u0010\\\u001a\u00020!8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bZ\u0010\u0014\u001a\u0004\b[\u0010%R\u001d\u0010_\u001a\u00020\u001b8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b]\u0010\u0014\u001a\u0004\b^\u0010\u001eR\u001d\u0010d\u001a\u00020`8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\ba\u0010\u0014\u001a\u0004\bb\u0010cR\u001d\u0010g\u001a\u00020\u001b8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\be\u0010\u0014\u001a\u0004\bf\u0010\u001eR\u001d\u0010j\u001a\u00020\u00128F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bh\u0010\u0014\u001a\u0004\bi\u0010\u0016R\u001d\u0010o\u001a\u00020k8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bl\u0010\u0014\u001a\u0004\bm\u0010nR\u001d\u0010r\u001a\u00020!8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bp\u0010\u0014\u001a\u0004\bq\u0010%R\u001d\u0010w\u001a\u00020s8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bt\u0010\u0014\u001a\u0004\bu\u0010vR\u001d\u0010z\u001a\u00020'8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bx\u0010\u0014\u001a\u0004\by\u0010*R\u001d\u0010\u007f\u001a\u00020{8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b|\u0010\u0014\u001a\u0004\b}\u0010~R \u0010\u0082\u0001\u001a\u00020!8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b\u0080\u0001\u0010\u0014\u001a\u0005\b\u0081\u0001\u0010%¨\u0006\u0085\u0001"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/novel/PlayModeFragment;", "Lcom/jbzd/media/movecartoons/core/MyThemeViewModelFragment;", "Lcom/jbzd/media/movecartoons/ui/novel/AudioPlayerViewModel;", "", "startAnimator", "()V", "stopAnimator", "", "getLayout", "()I", "initViews", "viewModelInstance", "()Lcom/jbzd/media/movecartoons/ui/novel/AudioPlayerViewModel;", "Lcom/jbzd/media/movecartoons/bean/event/EventMusic;", NotificationCompat.CATEGORY_EVENT, "onEvent", "(Lcom/jbzd/media/movecartoons/bean/event/EventMusic;)V", "onDestroy", "Landroid/view/View;", "circle_view$delegate", "Lkotlin/Lazy;", "getCircle_view", "()Landroid/view/View;", "circle_view", "Landroid/animation/ObjectAnimator;", "pointerAnimator", "Landroid/animation/ObjectAnimator;", "Lcom/jbzd/media/movecartoons/view/text/ImageTextView;", "itv_voicenovel_back_fifiteen$delegate", "getItv_voicenovel_back_fifiteen", "()Lcom/jbzd/media/movecartoons/view/text/ImageTextView;", "itv_voicenovel_back_fifiteen", "pointerAnimatorBig", "Landroid/widget/ImageView;", "kotlin.jvm.PlatformType", "musicPointer$delegate", "getMusicPointer", "()Landroid/widget/ImageView;", "musicPointer", "Landroid/widget/TextView;", "tv_voicenovel_time_cur$delegate", "getTv_voicenovel_time_cur", "()Landroid/widget/TextView;", "tv_voicenovel_time_cur", "albumAnimatorBig", "btn_play_pause$delegate", "getBtn_play_pause", "btn_play_pause", "turntableAnimator", "music_cover$delegate", "getMusic_cover", "music_cover", "tv_titleRight$delegate", "getTv_titleRight", "tv_titleRight", "tv_voicenovel_time_end$delegate", "getTv_voicenovel_time_end", "tv_voicenovel_time_end", "viewModel$delegate", "getViewModel", "viewModel", "musicTurntable$delegate", "getMusicTurntable", "musicTurntable", "turntableAnimatorBig", "iv_titleLeftIcon$delegate", "getIv_titleLeftIcon", "iv_titleLeftIcon", "", "mChapterId$delegate", "getMChapterId", "()Ljava/lang/String;", "mChapterId", "itv_voicenovel_fast_fifiteen$delegate", "getItv_voicenovel_fast_fifiteen", "itv_voicenovel_fast_fifiteen", "music_turntable$delegate", "getMusic_turntable", "music_turntable", "albumAnimator", "itv_voicenovel_chapter_list$delegate", "getItv_voicenovel_chapter_list", "itv_voicenovel_chapter_list", "Lcom/jbzd/media/movecartoons/bean/response/novel/NovelDetailInfoBean;", "mNovelDetailInfoBean$delegate", "getMNovelDetailInfoBean", "()Lcom/jbzd/media/movecartoons/bean/response/novel/NovelDetailInfoBean;", "mNovelDetailInfoBean", "tempMode", "Ljava/lang/String;", "iv_voicenovel_play_last$delegate", "getIv_voicenovel_play_last", "iv_voicenovel_play_last", "itv_voicenovel_timer$delegate", "getItv_voicenovel_timer", "itv_voicenovel_timer", "Lcom/jbzd/media/movecartoons/view/image/CircleImageView;", "music_album$delegate", "getMusic_album", "()Lcom/jbzd/media/movecartoons/view/image/CircleImageView;", "music_album", "itv_voicenovel_read_speed$delegate", "getItv_voicenovel_read_speed", "itv_voicenovel_read_speed", "overlay_view$delegate", "getOverlay_view", "overlay_view", "Landroid/widget/SeekBar;", "progress_bar$delegate", "getProgress_bar", "()Landroid/widget/SeekBar;", "progress_bar", "iv_voicenovel_play_next$delegate", "getIv_voicenovel_play_next", "iv_voicenovel_play_next", "Lcom/qunidayede/supportlibrary/widget/MarqueeTextView;", "tv_novelchapter_name$delegate", "getTv_novelchapter_name", "()Lcom/qunidayede/supportlibrary/widget/MarqueeTextView;", "tv_novelchapter_name", "tv_voicenovel_name$delegate", "getTv_voicenovel_name", "tv_voicenovel_name", "Landroid/widget/ProgressBar;", "loading_progress_bar$delegate", "getLoading_progress_bar", "()Landroid/widget/ProgressBar;", "loading_progress_bar", "music_pointer$delegate", "getMusic_pointer", "music_pointer", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class PlayModeFragment extends MyThemeViewModelFragment<AudioPlayerViewModel> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);
    private static final long DURATION_NORMAL_ROTATION = 1000;
    public static final long DURATION_SLOW_ROTATION = 25000;
    private static final float density;
    private static final float densityBig;
    private static final int dpValuePx = 120;
    private static final int dpValuePxBig = 180;
    private static final int dpValuePy = 40;
    private static final int dpValuePyBig = 80;
    private static final int pxValue;
    private static final int pxValueBig;
    private static final int pyValue;
    private static final int pyValueBig;

    @Nullable
    private ObjectAnimator albumAnimator;

    @Nullable
    private ObjectAnimator albumAnimatorBig;

    @Nullable
    private ObjectAnimator pointerAnimator;

    @Nullable
    private ObjectAnimator pointerAnimatorBig;

    @Nullable
    private ObjectAnimator turntableAnimator;

    @Nullable
    private ObjectAnimator turntableAnimatorBig;

    /* renamed from: musicTurntable$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy musicTurntable = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$musicTurntable$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        public final ImageView invoke() {
            return (ImageView) PlayModeFragment.this.requireView().findViewById(R.id.music_turntable);
        }
    });

    /* renamed from: musicPointer$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy musicPointer = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$musicPointer$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        public final ImageView invoke() {
            return (ImageView) PlayModeFragment.this.requireView().findViewById(R.id.music_pointer);
        }
    });

    @NotNull
    private String tempMode = "";

    /* renamed from: mNovelDetailInfoBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mNovelDetailInfoBean = LazyKt__LazyJVMKt.lazy(new Function0<NovelDetailInfoBean>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$mNovelDetailInfoBean$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final NovelDetailInfoBean invoke() {
            Bundle arguments = PlayModeFragment.this.getArguments();
            Serializable serializable = arguments == null ? null : arguments.getSerializable("novelDetailInfoBean");
            Objects.requireNonNull(serializable, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.novel.NovelDetailInfoBean");
            return (NovelDetailInfoBean) serializable;
        }
    });

    /* renamed from: mChapterId$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mChapterId = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$mChapterId$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final String invoke() {
            Bundle arguments = PlayModeFragment.this.getArguments();
            String string = arguments == null ? null : arguments.getString("CHAPTER_ID");
            Objects.requireNonNull(string, "null cannot be cast to non-null type kotlin.String");
            return string;
        }
    });

    /* renamed from: tv_novelchapter_name$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_novelchapter_name = LazyKt__LazyJVMKt.lazy(new Function0<MarqueeTextView>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$tv_novelchapter_name$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MarqueeTextView invoke() {
            View view = PlayModeFragment.this.getView();
            MarqueeTextView marqueeTextView = view == null ? null : (MarqueeTextView) view.findViewById(R.id.tv_novelchapter_name);
            Intrinsics.checkNotNull(marqueeTextView);
            return marqueeTextView;
        }
    });

    /* renamed from: circle_view$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy circle_view = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$circle_view$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final View invoke() {
            View view = PlayModeFragment.this.getView();
            View findViewById = view == null ? null : view.findViewById(R.id.circle_view);
            Intrinsics.checkNotNull(findViewById);
            return findViewById;
        }
    });

    /* renamed from: loading_progress_bar$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy loading_progress_bar = LazyKt__LazyJVMKt.lazy(new Function0<ProgressBar>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$loading_progress_bar$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ProgressBar invoke() {
            View view = PlayModeFragment.this.getView();
            ProgressBar progressBar = view == null ? null : (ProgressBar) view.findViewById(R.id.loading_progress_bar);
            Intrinsics.checkNotNull(progressBar);
            return progressBar;
        }
    });

    /* renamed from: overlay_view$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy overlay_view = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$overlay_view$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final View invoke() {
            View view = PlayModeFragment.this.getView();
            View findViewById = view == null ? null : view.findViewById(R.id.overlay_view);
            Intrinsics.checkNotNull(findViewById);
            return findViewById;
        }
    });

    /* renamed from: btn_play_pause$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy btn_play_pause = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$btn_play_pause$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            View view = PlayModeFragment.this.getView();
            ImageView imageView = view == null ? null : (ImageView) view.findViewById(R.id.btn_play_pause);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    /* renamed from: iv_titleLeftIcon$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_titleLeftIcon = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$iv_titleLeftIcon$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            View view = PlayModeFragment.this.getView();
            ImageView imageView = view == null ? null : (ImageView) view.findViewById(R.id.iv_titleLeftIcon);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    /* renamed from: tv_titleRight$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_titleRight = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$tv_titleRight$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            View view = PlayModeFragment.this.getView();
            TextView textView = view == null ? null : (TextView) view.findViewById(R.id.tv_titleRight);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_voicenovel_name$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_voicenovel_name = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$tv_voicenovel_name$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            View view = PlayModeFragment.this.getView();
            TextView textView = view == null ? null : (TextView) view.findViewById(R.id.tv_voicenovel_name);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: music_cover$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy music_cover = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$music_cover$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            View view = PlayModeFragment.this.getView();
            ImageView imageView = view == null ? null : (ImageView) view.findViewById(R.id.music_cover);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    /* renamed from: music_album$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy music_album = LazyKt__LazyJVMKt.lazy(new Function0<CircleImageView>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$music_album$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final CircleImageView invoke() {
            View view = PlayModeFragment.this.getView();
            CircleImageView circleImageView = view == null ? null : (CircleImageView) view.findViewById(R.id.music_album);
            Intrinsics.checkNotNull(circleImageView);
            return circleImageView;
        }
    });

    /* renamed from: progress_bar$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy progress_bar = LazyKt__LazyJVMKt.lazy(new Function0<SeekBar>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$progress_bar$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final SeekBar invoke() {
            View view = PlayModeFragment.this.getView();
            SeekBar seekBar = view == null ? null : (SeekBar) view.findViewById(R.id.progress_bar);
            Intrinsics.checkNotNull(seekBar);
            return seekBar;
        }
    });

    /* renamed from: itv_voicenovel_read_speed$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_voicenovel_read_speed = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$itv_voicenovel_read_speed$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageTextView invoke() {
            View view = PlayModeFragment.this.getView();
            ImageTextView imageTextView = view == null ? null : (ImageTextView) view.findViewById(R.id.itv_voicenovel_read_speed);
            Intrinsics.checkNotNull(imageTextView);
            return imageTextView;
        }
    });

    /* renamed from: itv_voicenovel_timer$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_voicenovel_timer = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$itv_voicenovel_timer$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageTextView invoke() {
            View view = PlayModeFragment.this.getView();
            ImageTextView imageTextView = view == null ? null : (ImageTextView) view.findViewById(R.id.itv_voicenovel_timer);
            Intrinsics.checkNotNull(imageTextView);
            return imageTextView;
        }
    });

    /* renamed from: itv_voicenovel_chapter_list$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_voicenovel_chapter_list = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$itv_voicenovel_chapter_list$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageTextView invoke() {
            View view = PlayModeFragment.this.getView();
            ImageTextView imageTextView = view == null ? null : (ImageTextView) view.findViewById(R.id.itv_voicenovel_chapter_list);
            Intrinsics.checkNotNull(imageTextView);
            return imageTextView;
        }
    });

    /* renamed from: iv_voicenovel_play_last$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_voicenovel_play_last = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$iv_voicenovel_play_last$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            View view = PlayModeFragment.this.getView();
            ImageView imageView = view == null ? null : (ImageView) view.findViewById(R.id.iv_voicenovel_play_last);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    /* renamed from: iv_voicenovel_play_next$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_voicenovel_play_next = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$iv_voicenovel_play_next$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            View view = PlayModeFragment.this.getView();
            ImageView imageView = view == null ? null : (ImageView) view.findViewById(R.id.iv_voicenovel_play_next);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    /* renamed from: itv_voicenovel_back_fifiteen$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_voicenovel_back_fifiteen = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$itv_voicenovel_back_fifiteen$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageTextView invoke() {
            View view = PlayModeFragment.this.getView();
            ImageTextView imageTextView = view == null ? null : (ImageTextView) view.findViewById(R.id.itv_voicenovel_back_fifiteen);
            Intrinsics.checkNotNull(imageTextView);
            return imageTextView;
        }
    });

    /* renamed from: itv_voicenovel_fast_fifiteen$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_voicenovel_fast_fifiteen = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$itv_voicenovel_fast_fifiteen$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageTextView invoke() {
            View view = PlayModeFragment.this.getView();
            ImageTextView imageTextView = view == null ? null : (ImageTextView) view.findViewById(R.id.itv_voicenovel_fast_fifiteen);
            Intrinsics.checkNotNull(imageTextView);
            return imageTextView;
        }
    });

    /* renamed from: tv_voicenovel_time_cur$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_voicenovel_time_cur = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$tv_voicenovel_time_cur$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            View view = PlayModeFragment.this.getView();
            TextView textView = view == null ? null : (TextView) view.findViewById(R.id.tv_voicenovel_time_cur);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_voicenovel_time_end$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_voicenovel_time_end = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$tv_voicenovel_time_end$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            View view = PlayModeFragment.this.getView();
            TextView textView = view == null ? null : (TextView) view.findViewById(R.id.tv_voicenovel_time_end);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: music_turntable$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy music_turntable = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$music_turntable$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            View view = PlayModeFragment.this.getView();
            ImageView imageView = view == null ? null : (ImageView) view.findViewById(R.id.music_turntable);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    /* renamed from: music_pointer$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy music_pointer = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$music_pointer$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            View view = PlayModeFragment.this.getView();
            ImageView imageView = view == null ? null : (ImageView) view.findViewById(R.id.music_pointer);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    /* renamed from: viewModel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy viewModel = FragmentViewModelLazyKt.createViewModelLazy(this, Reflection.getOrCreateKotlinClass(AudioPlayerViewModel.class), new Function0<ViewModelStore>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$special$$inlined$activityViewModels$default$1
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewModelStore invoke() {
            FragmentActivity requireActivity = Fragment.this.requireActivity();
            Intrinsics.checkExpressionValueIsNotNull(requireActivity, "requireActivity()");
            ViewModelStore viewModelStore = requireActivity.getViewModelStore();
            Intrinsics.checkExpressionValueIsNotNull(viewModelStore, "requireActivity().viewModelStore");
            return viewModelStore;
        }
    }, new Function0<ViewModelProvider.Factory>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$special$$inlined$activityViewModels$default$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewModelProvider.Factory invoke() {
            FragmentActivity requireActivity = Fragment.this.requireActivity();
            Intrinsics.checkExpressionValueIsNotNull(requireActivity, "requireActivity()");
            ViewModelProvider.Factory defaultViewModelProviderFactory = requireActivity.getDefaultViewModelProviderFactory();
            Intrinsics.checkExpressionValueIsNotNull(defaultViewModelProviderFactory, "requireActivity().defaultViewModelProviderFactory");
            return defaultViewModelProviderFactory;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00004\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\n\n\u0002\u0010\t\n\u0002\b\u0003\n\u0002\u0010\u0007\n\u0002\b\n\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b \u0010!J\u001d\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u0004¢\u0006\u0004\b\u0007\u0010\bR\u0019\u0010\n\u001a\u00020\t8\u0006@\u0006¢\u0006\f\n\u0004\b\n\u0010\u000b\u001a\u0004\b\f\u0010\rR\u0019\u0010\u000e\u001a\u00020\t8\u0006@\u0006¢\u0006\f\n\u0004\b\u000e\u0010\u000b\u001a\u0004\b\u000f\u0010\rR\u0019\u0010\u0010\u001a\u00020\t8\u0006@\u0006¢\u0006\f\n\u0004\b\u0010\u0010\u000b\u001a\u0004\b\u0011\u0010\rR\u0019\u0010\u0012\u001a\u00020\t8\u0006@\u0006¢\u0006\f\n\u0004\b\u0012\u0010\u000b\u001a\u0004\b\u0013\u0010\rR\u0016\u0010\u0015\u001a\u00020\u00148\u0002@\u0002X\u0082T¢\u0006\u0006\n\u0004\b\u0015\u0010\u0016R\u0016\u0010\u0017\u001a\u00020\u00148\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\u0017\u0010\u0016R\u0016\u0010\u0019\u001a\u00020\u00188\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\u0019\u0010\u001aR\u0016\u0010\u001b\u001a\u00020\u00188\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\u001b\u0010\u001aR\u0016\u0010\u001c\u001a\u00020\t8\u0002@\u0002X\u0082T¢\u0006\u0006\n\u0004\b\u001c\u0010\u000bR\u0016\u0010\u001d\u001a\u00020\t8\u0002@\u0002X\u0082T¢\u0006\u0006\n\u0004\b\u001d\u0010\u000bR\u0016\u0010\u001e\u001a\u00020\t8\u0002@\u0002X\u0082T¢\u0006\u0006\n\u0004\b\u001e\u0010\u000bR\u0016\u0010\u001f\u001a\u00020\t8\u0002@\u0002X\u0082T¢\u0006\u0006\n\u0004\b\u001f\u0010\u000b¨\u0006\""}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/novel/PlayModeFragment$Companion;", "", "Lcom/jbzd/media/movecartoons/bean/response/novel/NovelDetailInfoBean;", "novelDetailInfoBean", "", "chapterId", "Lcom/jbzd/media/movecartoons/ui/novel/PlayModeFragment;", "newInstance", "(Lcom/jbzd/media/movecartoons/bean/response/novel/NovelDetailInfoBean;Ljava/lang/String;)Lcom/jbzd/media/movecartoons/ui/novel/PlayModeFragment;", "", "pyValue", "I", "getPyValue", "()I", "pyValueBig", "getPyValueBig", "pxValueBig", "getPxValueBig", "pxValue", "getPxValue", "", "DURATION_NORMAL_ROTATION", "J", "DURATION_SLOW_ROTATION", "", "density", "F", "densityBig", "dpValuePx", "dpValuePxBig", "dpValuePy", "dpValuePyBig", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final int getPxValue() {
            return PlayModeFragment.pxValue;
        }

        public final int getPxValueBig() {
            return PlayModeFragment.pxValueBig;
        }

        public final int getPyValue() {
            return PlayModeFragment.pyValue;
        }

        public final int getPyValueBig() {
            return PlayModeFragment.pyValueBig;
        }

        @NotNull
        public final PlayModeFragment newInstance(@NotNull NovelDetailInfoBean novelDetailInfoBean, @NotNull String chapterId) {
            Intrinsics.checkNotNullParameter(novelDetailInfoBean, "novelDetailInfoBean");
            Intrinsics.checkNotNullParameter(chapterId, "chapterId");
            PlayModeFragment playModeFragment = new PlayModeFragment();
            Bundle bundle = new Bundle();
            bundle.putSerializable("novelDetailInfoBean", novelDetailInfoBean);
            bundle.putString("CHAPTER_ID", chapterId);
            Unit unit = Unit.INSTANCE;
            playModeFragment.setArguments(bundle);
            return playModeFragment;
        }
    }

    static {
        float f2 = Resources.getSystem().getDisplayMetrics().density;
        density = f2;
        pxValue = (int) ((120 * f2) + 0.5f);
        pyValue = (int) ((40 * f2) + 0.5f);
        float f3 = Resources.getSystem().getDisplayMetrics().density;
        densityBig = f3;
        pxValueBig = (int) ((180 * f3) + 0.5f);
        pyValueBig = (int) ((80 * f3) + 0.5f);
    }

    private final String getMChapterId() {
        return (String) this.mChapterId.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final NovelDetailInfoBean getMNovelDetailInfoBean() {
        return (NovelDetailInfoBean) this.mNovelDetailInfoBean.getValue();
    }

    private final ImageView getMusicPointer() {
        return (ImageView) this.musicPointer.getValue();
    }

    private final ImageView getMusicTurntable() {
        return (ImageView) this.musicTurntable.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-17$lambda-0, reason: not valid java name */
    public static final void m5928initViews$lambda17$lambda0(PlayModeFragment this$0, Boolean it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullExpressionValue(it, "it");
        if (it.booleanValue()) {
            BaseFragment.showLoadingDialog$default(this$0, null, true, 1, null);
            this$0.getCircle_view().setVisibility(0);
            this$0.getLoading_progress_bar().setVisibility(0);
            this$0.getOverlay_view().setVisibility(0);
            this$0.getBtn_play_pause().setVisibility(4);
            return;
        }
        this$0.hideLoadingDialog();
        this$0.getCircle_view().setVisibility(8);
        this$0.getLoading_progress_bar().setVisibility(8);
        this$0.getOverlay_view().setVisibility(8);
        this$0.getBtn_play_pause().setVisibility(0);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-17$lambda-1, reason: not valid java name */
    public static final void m5929initViews$lambda17$lambda1(final PlayModeFragment this$0, final AudioPlayerViewModel this_apply, NovelChapterInfoBean novelChapterInfoBean) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(this_apply, "$this_apply");
        this$0.getTv_voicenovel_name().setText(novelChapterInfoBean.chapter.name);
        C2354n.m2467d2(this$0.requireActivity()).m3298p(this$0.getMNovelDetailInfoBean().img).m3292f0().m757R(this$0.getMusic_cover());
        C2354n.m2467d2(this$0.requireActivity()).m3298p(this$0.getMNovelDetailInfoBean().img).m3292f0().m757R(this$0.getMusic_album());
        String str = novelChapterInfoBean.chapter.content;
        Intrinsics.checkNotNullExpressionValue(str, "it.chapter.content");
        this_apply.prepareMediaPlayertest(str, this$0.getProgress_bar(), new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$initViews$1$4$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
            /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue
            java.lang.NullPointerException: Cannot invoke "java.util.List.iterator()" because the return value of "jadx.core.dex.visitors.regions.SwitchOverStringVisitor$SwitchData.getNewCases()" is null
            	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.restoreSwitchOverString(SwitchOverStringVisitor.java:109)
            	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.visitRegion(SwitchOverStringVisitor.java:66)
            	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:77)
            	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:82)
             */
            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
                String str2;
                if (PlayModeFragment.this.isAdded()) {
                    AudioPlayerViewModel audioPlayerViewModel = this_apply;
                    Context requireContext = PlayModeFragment.this.requireContext();
                    Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                    final PlayModeFragment playModeFragment = PlayModeFragment.this;
                    audioPlayerViewModel.startPlaybackVM(requireContext, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$initViews$1$4$1.1
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
                            PlayModeFragment.this.startAnimator();
                        }
                    });
                    Objects.requireNonNull(this_apply.getService());
                    this_apply.getService().nextOrPrev = false;
                    this_apply.getService().speedMode.setValue("2");
                    ImageTextView itv_voicenovel_read_speed = PlayModeFragment.this.getItv_voicenovel_read_speed();
                    String value = this_apply.getService().speedMode.getValue();
                    if (value != null) {
                        switch (value.hashCode()) {
                            case 48:
                                if (value.equals("0")) {
                                    str2 = "语速 x0.5";
                                    break;
                                }
                                break;
                            case 49:
                                value.equals("1");
                                break;
                            case 50:
                                if (value.equals("2")) {
                                    str2 = "语速 x1.2";
                                    break;
                                }
                                break;
                            case 51:
                                if (value.equals("3")) {
                                    str2 = "语速 x1.5";
                                    break;
                                }
                                break;
                            case 52:
                                if (value.equals(HomeDataHelper.type_tag)) {
                                    str2 = "语速 x2.0";
                                    break;
                                }
                                break;
                        }
                        itv_voicenovel_read_speed.setText(str2);
                    }
                    str2 = "语速 x1.0";
                    itv_voicenovel_read_speed.setText(str2);
                }
            }
        }, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$initViews$1$4$2
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
                PlayModeFragment.this.stopAnimator();
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-17$lambda-11, reason: not valid java name */
    public static final void m5930initViews$lambda17$lambda11(PlayModeFragment this$0, AudioPlayerViewModel this_apply, View view) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(this_apply, "$this_apply");
        Context context = this$0.getContext();
        if (context == null) {
            return;
        }
        this_apply.playPrev(context);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-17$lambda-13, reason: not valid java name */
    public static final void m5931initViews$lambda17$lambda13(PlayModeFragment this$0, AudioPlayerViewModel this_apply, View view) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(this_apply, "$this_apply");
        if (this$0.getContext() == null) {
            return;
        }
        this_apply.playNext(new Function1<NovelChapter, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$initViews$1$18$1$1
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(NovelChapter novelChapter) {
                invoke2(novelChapter);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull NovelChapter it) {
                Intrinsics.checkNotNullParameter(it, "it");
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-17$lambda-14, reason: not valid java name */
    public static final void m5932initViews$lambda17$lambda14(final AudioPlayerViewModel this_apply, PlayModeFragment this$0, View view) {
        Intrinsics.checkNotNullParameter(this_apply, "$this_apply");
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        String currentThemeMode = this_apply.getCurrentThemeMode();
        String value = this_apply.getService()._mode.getValue();
        if (value == null) {
            value = "0";
        }
        String str = value;
        String value2 = this_apply.getService().endTime.getValue();
        if (value2 == null) {
            value2 = "00:00";
        }
        new TimingBottomDialog(currentThemeMode, str, value2, this_apply.getService().countdownTime, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$initViews$1$19$1
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
                AudioPlayerViewModel.this.getService().m4213o("0");
                AudioPlayerViewModel.this.getService().m4217s();
            }
        }, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$initViews$1$19$2
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
                AudioPlayerViewModel.this.getService().m4213o("1");
                AudioPlayerViewModel.this.getService().m4217s();
            }
        }, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$initViews$1$19$3
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
                AudioPlayerViewModel.this.getService().m4213o("2");
                AudioPlayerViewModel.this.getService().m4214p(15L);
            }
        }, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$initViews$1$19$4
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
                AudioPlayerViewModel.this.getService().m4213o("3");
                AudioPlayerViewModel.this.getService().m4214p(30L);
            }
        }, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$initViews$1$19$5
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
                AudioPlayerViewModel.this.getService().m4213o(HomeDataHelper.type_tag);
                AudioPlayerViewModel.this.getService().m4214p(60L);
            }
        }).show(this$0.getChildFragmentManager(), "TimingOrder");
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-17$lambda-15, reason: not valid java name */
    public static final void m5933initViews$lambda17$lambda15(final AudioPlayerViewModel this_apply, final PlayModeFragment this$0, View view) {
        Intrinsics.checkNotNullParameter(this_apply, "$this_apply");
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        String currentThemeMode = this_apply.getCurrentThemeMode();
        String value = this_apply.getService().speedMode.getValue();
        if (value == null) {
            value = "2";
        }
        new SpeedBottomDialog(currentThemeMode, value, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$initViews$1$20$1
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
                AudioPlayerViewModel.this.getService().speedMode.setValue("0");
                AudioPlayerViewModel.this.setPlaybackSpeed(0.5f);
                this$0.getItv_voicenovel_read_speed().setText("语速 x0.5");
            }
        }, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$initViews$1$20$2
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
                AudioPlayerViewModel.this.getService().speedMode.setValue("1");
                AudioPlayerViewModel.this.setPlaybackSpeed(1.0f);
                this$0.getItv_voicenovel_read_speed().setText("语速 x1.0");
            }
        }, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$initViews$1$20$3
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
                AudioPlayerViewModel.this.getService().speedMode.setValue("2");
                AudioPlayerViewModel.this.setPlaybackSpeed(1.2f);
                this$0.getItv_voicenovel_read_speed().setText("语速 x1.2");
            }
        }, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$initViews$1$20$4
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
                AudioPlayerViewModel.this.getService().speedMode.setValue("3");
                AudioPlayerViewModel.this.setPlaybackSpeed(1.5f);
                this$0.getItv_voicenovel_read_speed().setText("语速 x1.5");
            }
        }, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$initViews$1$20$5
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
                AudioPlayerViewModel.this.getService().speedMode.setValue(HomeDataHelper.type_tag);
                AudioPlayerViewModel.this.setPlaybackSpeed(2.0f);
                this$0.getItv_voicenovel_read_speed().setText("语速 x2.0");
            }
        }).show(this$0.getChildFragmentManager(), "TimingOrder");
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-17$lambda-16, reason: not valid java name */
    public static final void m5934initViews$lambda17$lambda16(PlayModeFragment this$0, View view) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.requireActivity().onBackPressed();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-17$lambda-2, reason: not valid java name */
    public static final void m5935initViews$lambda17$lambda2(final AudioPlayerViewModel this_apply, final PlayModeFragment this$0, final NovelChapterInfoBean it) {
        Intrinsics.checkNotNullParameter(this_apply, "$this_apply");
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        if (!this_apply.getService().isFromOutside && (!Intrinsics.areEqual(this_apply.getService().nowPlayingId, it.chapter.f10026id.toString()) || this_apply.getService().nextOrPrev)) {
            Intrinsics.checkNotNullExpressionValue(it, "it");
            String str = it.chapter.content;
            Intrinsics.checkNotNullExpressionValue(str, "it.chapter.content");
            this_apply.prepareMediaPlayer(it, str, this$0.getProgress_bar(), new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$initViews$1$5$1
                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                {
                    super(0);
                }

                @Override // kotlin.jvm.functions.Function0
                public /* bridge */ /* synthetic */ Unit invoke() {
                    invoke2();
                    return Unit.INSTANCE;
                }

                /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
                /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue
                java.lang.NullPointerException: Cannot invoke "java.util.List.iterator()" because the return value of "jadx.core.dex.visitors.regions.SwitchOverStringVisitor$SwitchData.getNewCases()" is null
                	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.restoreSwitchOverString(SwitchOverStringVisitor.java:109)
                	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.visitRegion(SwitchOverStringVisitor.java:66)
                	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:77)
                	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:82)
                 */
                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2() {
                    String str2;
                    if (PlayModeFragment.this.isAdded()) {
                        AudioPlayerViewModel audioPlayerViewModel = this_apply;
                        Context requireContext = PlayModeFragment.this.requireContext();
                        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                        final PlayModeFragment playModeFragment = PlayModeFragment.this;
                        audioPlayerViewModel.startPlaybackVM(requireContext, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$initViews$1$5$1.1
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
                                PlayModeFragment.this.startAnimator();
                            }
                        });
                        Objects.requireNonNull(this_apply.getService());
                        this_apply.getService().nowPlayingId = it.chapter.f10026id.toString();
                        this_apply.getService().nextOrPrev = false;
                        this_apply.getService().speedMode.setValue("2");
                        ImageTextView itv_voicenovel_read_speed = PlayModeFragment.this.getItv_voicenovel_read_speed();
                        String value = this_apply.getService().speedMode.getValue();
                        if (value != null) {
                            switch (value.hashCode()) {
                                case 48:
                                    if (value.equals("0")) {
                                        str2 = "语速 x0.5";
                                        break;
                                    }
                                    break;
                                case 49:
                                    value.equals("1");
                                    break;
                                case 50:
                                    if (value.equals("2")) {
                                        str2 = "语速 x1.2";
                                        break;
                                    }
                                    break;
                                case 51:
                                    if (value.equals("3")) {
                                        str2 = "语速 x1.5";
                                        break;
                                    }
                                    break;
                                case 52:
                                    if (value.equals(HomeDataHelper.type_tag)) {
                                        str2 = "语速 x2.0";
                                        break;
                                    }
                                    break;
                            }
                            itv_voicenovel_read_speed.setText(str2);
                        }
                        str2 = "语速 x1.0";
                        itv_voicenovel_read_speed.setText(str2);
                    }
                }
            }, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$initViews$1$5$2
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
                    PlayModeFragment.this.stopAnimator();
                }
            });
        }
        this_apply.getService().isFromOutside = false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-17$lambda-3, reason: not valid java name */
    public static final void m5936initViews$lambda17$lambda3(AudioPlayerViewModel this_apply, Integer position) {
        Intrinsics.checkNotNullParameter(this_apply, "$this_apply");
        Intrinsics.checkNotNullExpressionValue(position, "position");
        this_apply.updatePlaybackTime(position.intValue());
        this_apply.getLoadingProgressBar().setValue(Boolean.FALSE);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-17$lambda-4, reason: not valid java name */
    public static final void m5937initViews$lambda17$lambda4(AudioPlayerViewModel this_apply, PlayModeFragment this$0, Boolean bool) {
        Intrinsics.checkNotNullParameter(this_apply, "$this_apply");
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        if (this_apply.getService().mediaPlayer.isPlaying()) {
            this$0.startAnimator();
        } else {
            this$0.stopAnimator();
        }
        this$0.getBtn_play_pause().setImageResource(this_apply.getService().mediaPlayer.isPlaying() ? R.drawable.play_bar_play_stop : R.drawable.play_bar_play_start);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-17$lambda-5, reason: not valid java name */
    public static final void m5938initViews$lambda17$lambda5(AudioPlayerViewModel this_apply, final PlayModeFragment this$0, View view) {
        Intrinsics.checkNotNullParameter(this_apply, "$this_apply");
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        if (this_apply.getService().mediaPlayer.isPlaying()) {
            Context requireContext = this$0.requireContext();
            Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
            this_apply.pausePlaybackVM(requireContext, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$initViews$1$12$1
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
                    PlayModeFragment.this.stopAnimator();
                }
            });
        } else {
            if (this$0.getProgress_bar().getProgress() == 0) {
                this$0.getProgress_bar().setMax(this_apply.getService().mediaPlayer.getDuration());
            }
            Context requireContext2 = this$0.requireContext();
            Intrinsics.checkNotNullExpressionValue(requireContext2, "requireContext()");
            this_apply.startPlaybackVM(requireContext2, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$initViews$1$12$2
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
                    PlayModeFragment.this.startAnimator();
                }
            });
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-17$lambda-6, reason: not valid java name */
    public static final void m5939initViews$lambda17$lambda6(PlayModeFragment this$0, String str) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.getTv_voicenovel_time_cur().setText(str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-17$lambda-7, reason: not valid java name */
    public static final void m5940initViews$lambda17$lambda7(PlayModeFragment this$0, String str) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.getTv_voicenovel_time_end().setText(str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-17$lambda-8, reason: not valid java name */
    public static final void m5941initViews$lambda17$lambda8(AudioPlayerViewModel this_apply, View view) {
        Intrinsics.checkNotNullParameter(this_apply, "$this_apply");
        this_apply.getService().m4212n(-15000);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-17$lambda-9, reason: not valid java name */
    public static final void m5942initViews$lambda17$lambda9(AudioPlayerViewModel this_apply, View view) {
        Intrinsics.checkNotNullParameter(this_apply, "$this_apply");
        this_apply.getService().m4212n(15000);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void startAnimator() {
        ObjectAnimator objectAnimator = this.albumAnimator;
        if (objectAnimator == null) {
            ObjectAnimator ofFloat = ObjectAnimator.ofFloat(getMusicTurntable(), Key.ROTATION, 0.0f, 360.0f);
            this.albumAnimator = ofFloat;
            if (ofFloat != null) {
                ofFloat.setDuration(DURATION_SLOW_ROTATION);
            }
            ObjectAnimator objectAnimator2 = this.albumAnimator;
            if (objectAnimator2 != null) {
                objectAnimator2.setRepeatCount(-1);
            }
            ObjectAnimator objectAnimator3 = this.albumAnimator;
            if (objectAnimator3 != null) {
                objectAnimator3.setInterpolator(new LinearInterpolator());
            }
            ObjectAnimator ofFloat2 = ObjectAnimator.ofFloat(getMusicTurntable(), Key.ROTATION, 0.0f, 360.0f);
            this.turntableAnimator = ofFloat2;
            if (ofFloat2 != null) {
                ofFloat2.setDuration(DURATION_SLOW_ROTATION);
            }
            ObjectAnimator objectAnimator4 = this.turntableAnimator;
            if (objectAnimator4 != null) {
                objectAnimator4.setRepeatCount(-1);
            }
            ObjectAnimator objectAnimator5 = this.turntableAnimator;
            if (objectAnimator5 != null) {
                objectAnimator5.setInterpolator(new LinearInterpolator());
            }
            ObjectAnimator objectAnimator6 = this.albumAnimator;
            if (objectAnimator6 != null) {
                objectAnimator6.start();
            }
            ObjectAnimator objectAnimator7 = this.turntableAnimator;
            if (objectAnimator7 != null) {
                objectAnimator7.start();
            }
        } else {
            if (objectAnimator != null) {
                objectAnimator.resume();
            }
            ObjectAnimator objectAnimator8 = this.turntableAnimator;
            if (objectAnimator8 != null) {
                objectAnimator8.resume();
            }
        }
        ObjectAnimator objectAnimator9 = this.albumAnimatorBig;
        if (objectAnimator9 == null) {
            ObjectAnimator ofFloat3 = ObjectAnimator.ofFloat(getMusic_album(), Key.ROTATION, 0.0f, 360.0f);
            this.albumAnimatorBig = ofFloat3;
            if (ofFloat3 != null) {
                ofFloat3.setDuration(DURATION_SLOW_ROTATION);
            }
            ObjectAnimator objectAnimator10 = this.albumAnimatorBig;
            if (objectAnimator10 != null) {
                objectAnimator10.setRepeatCount(-1);
            }
            ObjectAnimator objectAnimator11 = this.albumAnimatorBig;
            if (objectAnimator11 != null) {
                objectAnimator11.setInterpolator(new LinearInterpolator());
            }
            ObjectAnimator objectAnimator12 = this.albumAnimatorBig;
            if (objectAnimator12 != null) {
                objectAnimator12.start();
            }
            ObjectAnimator ofFloat4 = ObjectAnimator.ofFloat(getMusic_turntable(), Key.ROTATION, 0.0f, 360.0f);
            this.turntableAnimatorBig = ofFloat4;
            if (ofFloat4 != null) {
                ofFloat4.setDuration(DURATION_SLOW_ROTATION);
            }
            ObjectAnimator objectAnimator13 = this.turntableAnimatorBig;
            if (objectAnimator13 != null) {
                objectAnimator13.setRepeatCount(-1);
            }
            ObjectAnimator objectAnimator14 = this.turntableAnimatorBig;
            if (objectAnimator14 != null) {
                objectAnimator14.setInterpolator(new LinearInterpolator());
            }
            ObjectAnimator objectAnimator15 = this.turntableAnimatorBig;
            if (objectAnimator15 != null) {
                objectAnimator15.start();
            }
        } else {
            if (objectAnimator9 != null) {
                objectAnimator9.resume();
            }
            ObjectAnimator objectAnimator16 = this.turntableAnimatorBig;
            if (objectAnimator16 != null) {
                objectAnimator16.resume();
            }
        }
        float f2 = 10;
        getMusicPointer().setPivotX(pxValue - f2);
        float f3 = 2;
        getMusicPointer().setPivotY((pyValue / f3) + f2);
        ObjectAnimator ofFloat5 = ObjectAnimator.ofFloat(getMusicPointer(), Key.ROTATION, 0.0f, -20.0f);
        this.pointerAnimator = ofFloat5;
        if (ofFloat5 != null) {
            ofFloat5.setDuration(DURATION_NORMAL_ROTATION);
        }
        ObjectAnimator objectAnimator17 = this.pointerAnimator;
        if (objectAnimator17 != null) {
            objectAnimator17.setRepeatCount(0);
        }
        ObjectAnimator objectAnimator18 = this.pointerAnimator;
        if (objectAnimator18 != null) {
            objectAnimator18.setRepeatMode(1);
        }
        ObjectAnimator objectAnimator19 = this.pointerAnimator;
        if (objectAnimator19 != null) {
            objectAnimator19.start();
        }
        getMusic_pointer().setPivotX(pxValueBig - f2);
        getMusic_pointer().setPivotY((pyValueBig / f3) + f2);
        ObjectAnimator ofFloat6 = ObjectAnimator.ofFloat(getMusic_pointer(), Key.ROTATION, 0.0f, -20.0f);
        this.pointerAnimatorBig = ofFloat6;
        if (ofFloat6 != null) {
            ofFloat6.setDuration(DURATION_NORMAL_ROTATION);
        }
        ObjectAnimator objectAnimator20 = this.pointerAnimatorBig;
        if (objectAnimator20 != null) {
            objectAnimator20.setRepeatCount(0);
        }
        ObjectAnimator objectAnimator21 = this.pointerAnimatorBig;
        if (objectAnimator21 != null) {
            objectAnimator21.setRepeatMode(1);
        }
        ObjectAnimator objectAnimator22 = this.pointerAnimatorBig;
        if (objectAnimator22 == null) {
            return;
        }
        objectAnimator22.start();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void stopAnimator() {
        ObjectAnimator objectAnimator = this.pointerAnimator;
        if (objectAnimator != null) {
            objectAnimator.pause();
            objectAnimator.setFloatValues(getMusicPointer().getRotation(), 0.0f);
            objectAnimator.setRepeatMode(2);
            objectAnimator.start();
        }
        ObjectAnimator objectAnimator2 = this.albumAnimator;
        if (objectAnimator2 != null) {
            objectAnimator2.pause();
        }
        ObjectAnimator objectAnimator3 = this.turntableAnimator;
        if (objectAnimator3 != null) {
            objectAnimator3.pause();
        }
        ObjectAnimator objectAnimator4 = this.pointerAnimatorBig;
        if (objectAnimator4 != null) {
            objectAnimator4.pause();
            objectAnimator4.setFloatValues(getMusic_pointer().getRotation(), 0.0f);
            objectAnimator4.setRepeatMode(2);
            objectAnimator4.start();
        }
        ObjectAnimator objectAnimator5 = this.albumAnimatorBig;
        if (objectAnimator5 != null) {
            objectAnimator5.pause();
        }
        ObjectAnimator objectAnimator6 = this.turntableAnimatorBig;
        if (objectAnimator6 == null) {
            return;
        }
        objectAnimator6.pause();
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeViewModelFragment, com.qunidayede.supportlibrary.core.view.BaseThemeViewModelFragment, com.qunidayede.supportlibrary.core.view.BaseViewModelFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @NotNull
    public final ImageView getBtn_play_pause() {
        return (ImageView) this.btn_play_pause.getValue();
    }

    @NotNull
    public final View getCircle_view() {
        return (View) this.circle_view.getValue();
    }

    @NotNull
    public final ImageTextView getItv_voicenovel_back_fifiteen() {
        return (ImageTextView) this.itv_voicenovel_back_fifiteen.getValue();
    }

    @NotNull
    public final ImageTextView getItv_voicenovel_chapter_list() {
        return (ImageTextView) this.itv_voicenovel_chapter_list.getValue();
    }

    @NotNull
    public final ImageTextView getItv_voicenovel_fast_fifiteen() {
        return (ImageTextView) this.itv_voicenovel_fast_fifiteen.getValue();
    }

    @NotNull
    public final ImageTextView getItv_voicenovel_read_speed() {
        return (ImageTextView) this.itv_voicenovel_read_speed.getValue();
    }

    @NotNull
    public final ImageTextView getItv_voicenovel_timer() {
        return (ImageTextView) this.itv_voicenovel_timer.getValue();
    }

    @NotNull
    public final ImageView getIv_titleLeftIcon() {
        return (ImageView) this.iv_titleLeftIcon.getValue();
    }

    @NotNull
    public final ImageView getIv_voicenovel_play_last() {
        return (ImageView) this.iv_voicenovel_play_last.getValue();
    }

    @NotNull
    public final ImageView getIv_voicenovel_play_next() {
        return (ImageView) this.iv_voicenovel_play_next.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public int getLayout() {
        return R.layout.act_novel_playing;
    }

    @NotNull
    public final ProgressBar getLoading_progress_bar() {
        return (ProgressBar) this.loading_progress_bar.getValue();
    }

    @NotNull
    public final CircleImageView getMusic_album() {
        return (CircleImageView) this.music_album.getValue();
    }

    @NotNull
    public final ImageView getMusic_cover() {
        return (ImageView) this.music_cover.getValue();
    }

    @NotNull
    public final ImageView getMusic_pointer() {
        return (ImageView) this.music_pointer.getValue();
    }

    @NotNull
    public final ImageView getMusic_turntable() {
        return (ImageView) this.music_turntable.getValue();
    }

    @NotNull
    public final View getOverlay_view() {
        return (View) this.overlay_view.getValue();
    }

    @NotNull
    public final SeekBar getProgress_bar() {
        return (SeekBar) this.progress_bar.getValue();
    }

    @NotNull
    public final MarqueeTextView getTv_novelchapter_name() {
        return (MarqueeTextView) this.tv_novelchapter_name.getValue();
    }

    @NotNull
    public final TextView getTv_titleRight() {
        return (TextView) this.tv_titleRight.getValue();
    }

    @NotNull
    public final TextView getTv_voicenovel_name() {
        return (TextView) this.tv_voicenovel_name.getValue();
    }

    @NotNull
    public final TextView getTv_voicenovel_time_cur() {
        return (TextView) this.tv_voicenovel_time_cur.getValue();
    }

    @NotNull
    public final TextView getTv_voicenovel_time_end() {
        return (TextView) this.tv_voicenovel_time_end.getValue();
    }

    @NotNull
    public final AudioPlayerViewModel getViewModel() {
        return (AudioPlayerViewModel) this.viewModel.getValue();
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue
    java.lang.NullPointerException: Cannot invoke "java.util.List.iterator()" because the return value of "jadx.core.dex.visitors.regions.SwitchOverStringVisitor$SwitchData.getNewCases()" is null
    	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.restoreSwitchOverString(SwitchOverStringVisitor.java:109)
    	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.visitRegion(SwitchOverStringVisitor.java:66)
    	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:77)
    	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:82)
     */
    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    @RequiresApi(23)
    public void initViews() {
        String str;
        super.initViews();
        C4909c.m5569b().m5578k(this);
        getTv_novelchapter_name().m4583c();
        final AudioPlayerViewModel viewModel = getViewModel();
        viewModel.getLoadingProgressBar().setValue(Boolean.TRUE);
        viewModel.getLoadingProgressBar().observe(this, new Observer() { // from class: b.a.a.a.t.j.f0
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                PlayModeFragment.m5928initViews$lambda17$lambda0(PlayModeFragment.this, (Boolean) obj);
            }
        });
        C2354n.m2374A(getIv_titleLeftIcon(), 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$initViews$1$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageView imageView) {
                invoke2(imageView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ImageView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                if (AudioPlayerViewModel.this.getService().mediaPlayer.isPlaying()) {
                    AudioPlayerViewModel audioPlayerViewModel = AudioPlayerViewModel.this;
                    Context requireContext = this.requireContext();
                    Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                    final PlayModeFragment playModeFragment = this;
                    audioPlayerViewModel.pausePlaybackVM(requireContext, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$initViews$1$2.1
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
                            PlayModeFragment.this.stopAnimator();
                        }
                    });
                }
                FragmentActivity activity = this.getActivity();
                if (activity == null) {
                    return;
                }
                activity.finish();
            }
        }, 1);
        C2354n.m2374A(getTv_titleRight(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$initViews$1$3
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView) {
                invoke2(textView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull TextView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                if (AudioPlayerViewModel.this.getService().mediaPlayer.isPlaying()) {
                    AudioPlayerViewModel audioPlayerViewModel = AudioPlayerViewModel.this;
                    Context requireContext = this.requireContext();
                    Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                    final PlayModeFragment playModeFragment = this;
                    audioPlayerViewModel.pausePlaybackVM(requireContext, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$initViews$1$3.1
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
                            PlayModeFragment.this.stopAnimator();
                        }
                    });
                }
                InviteActivity.Companion companion = InviteActivity.INSTANCE;
                Context requireContext2 = this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext2, "requireContext()");
                companion.start(requireContext2);
            }
        }, 1);
        viewModel.getNovelChapterInfoBean().observe(this, new Observer() { // from class: b.a.a.a.t.j.z
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                PlayModeFragment.m5929initViews$lambda17$lambda1(PlayModeFragment.this, viewModel, (NovelChapterInfoBean) obj);
            }
        });
        viewModel.getNovelChapterInfoBean().observe(getViewLifecycleOwner(), new Observer() { // from class: b.a.a.a.t.j.x
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                PlayModeFragment.m5935initViews$lambda17$lambda2(AudioPlayerViewModel.this, this, (NovelChapterInfoBean) obj);
            }
        });
        if (viewModel.getService().mediaPlayer.isPlaying()) {
            AudioPlayerViewModel.prepareMediaPlayer$default(viewModel, new NovelChapterInfoBean(), null, getProgress_bar(), new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$initViews$1$6
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
                    AudioPlayerViewModel audioPlayerViewModel = AudioPlayerViewModel.this;
                    Context requireContext = this.requireContext();
                    Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                    final PlayModeFragment playModeFragment = this;
                    audioPlayerViewModel.startPlaybackVM(requireContext, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$initViews$1$6.1
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
                            PlayModeFragment.this.startAnimator();
                        }
                    });
                }
            }, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$initViews$1$7
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
                    PlayModeFragment.this.stopAnimator();
                }
            }, 2, null);
        } else {
            getProgress_bar().setMax(viewModel.getService().mediaPlayer.getDuration());
        }
        viewModel.getService().currentPosition.observe(getViewLifecycleOwner(), new Observer() { // from class: b.a.a.a.t.j.d0
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                PlayModeFragment.m5936initViews$lambda17$lambda3(AudioPlayerViewModel.this, (Integer) obj);
            }
        });
        getProgress_bar().setOnSeekBarChangeListener(new SeekBar.OnSeekBarChangeListener() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$initViews$1$9
            @Override // android.widget.SeekBar.OnSeekBarChangeListener
            public void onProgressChanged(@Nullable SeekBar seekBar, int progress, boolean fromUser) {
                if (fromUser) {
                    AudioPlayerViewModel audioPlayerViewModel = AudioPlayerViewModel.this;
                    Context requireContext = this.requireContext();
                    Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                    audioPlayerViewModel.seekToPositionVM(requireContext, progress);
                }
            }

            @Override // android.widget.SeekBar.OnSeekBarChangeListener
            public void onStartTrackingTouch(@Nullable SeekBar seekBar) {
            }

            @Override // android.widget.SeekBar.OnSeekBarChangeListener
            public void onStopTrackingTouch(@Nullable SeekBar seekBar) {
            }
        });
        viewModel.getService().isPlaying.observe(getViewLifecycleOwner(), new Observer() { // from class: b.a.a.a.t.j.u
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                PlayModeFragment.m5937initViews$lambda17$lambda4(AudioPlayerViewModel.this, this, (Boolean) obj);
            }
        });
        MyThemeViewModelFragment.fadeWhenTouch$default(this, getItv_voicenovel_timer(), 0.0f, 1, null);
        MyThemeViewModelFragment.fadeWhenTouch$default(this, getItv_voicenovel_read_speed(), 0.0f, 1, null);
        MyThemeViewModelFragment.fadeWhenTouch$default(this, getItv_voicenovel_chapter_list(), 0.0f, 1, null);
        C2354n.m2374A(getItv_voicenovel_chapter_list(), 0L, new Function1<ImageTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$initViews$1$11
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageTextView imageTextView) {
                invoke2(imageTextView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ImageTextView it) {
                NovelDetailInfoBean mNovelDetailInfoBean;
                Intrinsics.checkNotNullParameter(it, "it");
                NovelTableContentAllActivity.Companion companion = NovelTableContentAllActivity.INSTANCE;
                Context requireContext = PlayModeFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                mNovelDetailInfoBean = PlayModeFragment.this.getMNovelDetailInfoBean();
                companion.start(requireContext, mNovelDetailInfoBean);
                if (PlayModeFragment.this.getViewModel().getService().mediaPlayer.isPlaying()) {
                    AudioPlayerViewModel viewModel2 = PlayModeFragment.this.getViewModel();
                    Context requireContext2 = PlayModeFragment.this.requireContext();
                    Intrinsics.checkNotNullExpressionValue(requireContext2, "requireContext()");
                    final PlayModeFragment playModeFragment = PlayModeFragment.this;
                    viewModel2.pausePlaybackVM(requireContext2, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$initViews$1$11.1
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
                            PlayModeFragment.this.stopAnimator();
                        }
                    });
                }
            }
        }, 1);
        MyThemeViewModelFragment.fadeWhenTouch$default(this, getIv_voicenovel_play_last(), 0.0f, 1, null);
        MyThemeViewModelFragment.fadeWhenTouch$default(this, getIv_voicenovel_play_next(), 0.0f, 1, null);
        MyThemeViewModelFragment.fadeWhenTouch$default(this, getBtn_play_pause(), 0.0f, 1, null);
        MyThemeViewModelFragment.fadeWhenTouch$default(this, getItv_voicenovel_back_fifiteen(), 0.0f, 1, null);
        MyThemeViewModelFragment.fadeWhenTouch$default(this, getItv_voicenovel_fast_fifiteen(), 0.0f, 1, null);
        getBtn_play_pause().setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.t.j.t
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                PlayModeFragment.m5938initViews$lambda17$lambda5(AudioPlayerViewModel.this, this, view);
            }
        });
        viewModel.getService().startTime.observe(getViewLifecycleOwner(), new Observer() { // from class: b.a.a.a.t.j.a0
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                PlayModeFragment.m5939initViews$lambda17$lambda6(PlayModeFragment.this, (String) obj);
            }
        });
        viewModel.getService().endTime.observe(getViewLifecycleOwner(), new Observer() { // from class: b.a.a.a.t.j.w
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                PlayModeFragment.m5940initViews$lambda17$lambda7(PlayModeFragment.this, (String) obj);
            }
        });
        getItv_voicenovel_back_fifiteen().setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.t.j.g0
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                PlayModeFragment.m5941initViews$lambda17$lambda8(AudioPlayerViewModel.this, view);
            }
        });
        getItv_voicenovel_fast_fifiteen().setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.t.j.c0
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                PlayModeFragment.m5942initViews$lambda17$lambda9(AudioPlayerViewModel.this, view);
            }
        });
        getIv_voicenovel_play_last().setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.t.j.e0
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                PlayModeFragment.m5930initViews$lambda17$lambda11(PlayModeFragment.this, viewModel, view);
            }
        });
        getIv_voicenovel_play_next().setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.t.j.y
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                PlayModeFragment.m5931initViews$lambda17$lambda13(PlayModeFragment.this, viewModel, view);
            }
        });
        getItv_voicenovel_timer().setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.t.j.h0
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                PlayModeFragment.m5932initViews$lambda17$lambda14(AudioPlayerViewModel.this, this, view);
            }
        });
        getItv_voicenovel_read_speed().setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.t.j.v
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                PlayModeFragment.m5933initViews$lambda17$lambda15(AudioPlayerViewModel.this, this, view);
            }
        });
        ImageTextView itv_voicenovel_read_speed = getItv_voicenovel_read_speed();
        String value = viewModel.getService().speedMode.getValue();
        if (value != null) {
            switch (value.hashCode()) {
                case 48:
                    if (value.equals("0")) {
                        str = "语速 x0.5";
                        break;
                    }
                    break;
                case 49:
                    value.equals("1");
                    break;
                case 50:
                    if (value.equals("2")) {
                        str = "语速 x1.2";
                        break;
                    }
                    break;
                case 51:
                    if (value.equals("3")) {
                        str = "语速 x1.5";
                        break;
                    }
                    break;
                case 52:
                    if (value.equals(HomeDataHelper.type_tag)) {
                        str = "语速 x2.0";
                        break;
                    }
                    break;
            }
            itv_voicenovel_read_speed.setText(str);
            getMusic_album().setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.t.j.b0
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    PlayModeFragment.m5934initViews$lambda17$lambda16(PlayModeFragment.this, view);
                }
            });
        }
        str = "语速 x1.0";
        itv_voicenovel_read_speed.setText(str);
        getMusic_album().setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.t.j.b0
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                PlayModeFragment.m5934initViews$lambda17$lambda16(PlayModeFragment.this, view);
            }
        });
    }

    @Override // androidx.fragment.app.Fragment
    public void onDestroy() {
        super.onDestroy();
        C4909c.m5569b().m5580m(this);
    }

    @InterfaceC4919m
    public final void onEvent(@NotNull EventMusic event) {
        Intrinsics.checkNotNullParameter(event, "event");
        if (StringsKt__StringsJVMKt.equals$default(event.getType(), "play", false, 2, null)) {
            if (event.getChapterListBean() != null) {
                getTv_voicenovel_name().setText(event.getChapterListBean().name);
            }
            AudioPlayerViewModel viewModel = getViewModel();
            Context requireContext = requireContext();
            Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
            viewModel.startPlaybackVM(requireContext, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$onEvent$1
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
                    PlayModeFragment.this.startAnimator();
                }
            });
            return;
        }
        if (StringsKt__StringsJVMKt.equals$default(event.getType(), "pause", false, 2, null)) {
            AudioPlayerViewModel viewModel2 = getViewModel();
            Context requireContext2 = requireContext();
            Intrinsics.checkNotNullExpressionValue(requireContext2, "requireContext()");
            viewModel2.pausePlaybackVM(requireContext2, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.PlayModeFragment$onEvent$2
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
                    PlayModeFragment.this.stopAnimator();
                }
            });
            return;
        }
        if (StringsKt__StringsJVMKt.equals$default(event.getType(), "harmony", false, 2, null)) {
            stopAnimator();
            return;
        }
        if (StringsKt__StringsJVMKt.equals$default(event.getType(), "cantPlay", false, 2, null)) {
            NovelChapter chapterListBean = event.getChapterListBean();
            if (StringsKt__StringsJVMKt.equals$default(chapterListBean == null ? null : chapterListBean.type, VideoTypeBean.video_type_vip, false, 2, null)) {
                new PostVipDialog(null, 1, null).show(getChildFragmentManager(), "postVipDialog");
                return;
            } else {
                event.getChapterListBean();
                return;
            }
        }
        if (StringsKt__StringsJVMKt.equals$default(event.getType(), "progressMax", false, 2, null)) {
            SeekBar progress_bar = getProgress_bar();
            Integer pos = event.getPos();
            Intrinsics.checkNotNull(pos);
            progress_bar.setMax(pos.intValue());
            return;
        }
        if (StringsKt__StringsJVMKt.equals$default(event.getType(), "setOnErrorListener", false, 2, null)) {
            hideLoadingDialog();
            getCircle_view().setVisibility(8);
            getLoading_progress_bar().setVisibility(0);
            getOverlay_view().setVisibility(8);
            getBtn_play_pause().setVisibility(0);
        }
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseViewModelFragment
    @NotNull
    public AudioPlayerViewModel viewModelInstance() {
        FragmentActivity activity = getActivity();
        Objects.requireNonNull(activity, "null cannot be cast to non-null type com.jbzd.media.movecartoons.ui.novel.AudioPlayerActivity");
        return ((AudioPlayerActivity) activity).getViewModel();
    }
}

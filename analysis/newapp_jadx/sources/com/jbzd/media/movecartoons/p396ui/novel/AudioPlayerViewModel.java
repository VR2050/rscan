package com.jbzd.media.movecartoons.p396ui.novel;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.media.PlaybackParams;
import android.widget.SeekBar;
import androidx.annotation.RequiresApi;
import androidx.core.app.NotificationCompat;
import androidx.lifecycle.MutableLiveData;
import androidx.lifecycle.ViewModelKt;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;
import com.jbzd.media.movecartoons.bean.response.ChapterInfoBean;
import com.jbzd.media.movecartoons.bean.response.FindBean;
import com.jbzd.media.movecartoons.bean.response.InfoBean;
import com.jbzd.media.movecartoons.bean.response.novel.NovelChapter;
import com.jbzd.media.movecartoons.bean.response.novel.NovelChapterInfoBean;
import com.jbzd.media.movecartoons.bean.response.novel.NovelDetailInfoBean;
import com.jbzd.media.movecartoons.service.AudioPlayerService;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.StringCompanionObject;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p006a.p007a.p008a.p023s.C0959d0;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.C2827a;
import p005b.p327w.p330b.p331b.ApplicationC2828a;
import p005b.p327w.p330b.p331b.p335f.C2848a;
import p379c.p380a.InterfaceC3053d1;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u008c\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u000b\n\u0002\b\b\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010\b\n\u0002\b\r\n\u0002\u0010\u0007\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u001c\n\u0002\u0018\u0002\n\u0002\b\u000b\n\u0002\u0018\u0002\n\u0002\b\u001e\n\u0002\u0018\u0002\n\u0002\b\u0006\u0018\u00002\u00020\u0001B\b¢\u0006\u0005\b\u009b\u0001\u0010\u0004J\u000f\u0010\u0003\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0003\u0010\u0004J\u000f\u0010\u0005\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\u0005\u0010\u0004J\u001f\u0010\n\u001a\u00020\u00022\u0006\u0010\u0007\u001a\u00020\u00062\b\b\u0002\u0010\t\u001a\u00020\b¢\u0006\u0004\b\n\u0010\u000bJ)\u0010\u000e\u001a\u00020\u00022\u0006\u0010\f\u001a\u00020\u00062\b\b\u0002\u0010\t\u001a\u00020\b2\b\b\u0002\u0010\r\u001a\u00020\u0006¢\u0006\u0004\b\u000e\u0010\u000fJ;\u0010\u0016\u001a\u00020\u00022\b\b\u0002\u0010\u0010\u001a\u00020\u00062\u0006\u0010\u0012\u001a\u00020\u00112\f\u0010\u0014\u001a\b\u0012\u0004\u0012\u00020\u00020\u00132\f\u0010\u0015\u001a\b\u0012\u0004\u0012\u00020\u00020\u0013¢\u0006\u0004\b\u0016\u0010\u0017JC\u0010\u001a\u001a\u00020\u00022\u0006\u0010\u0019\u001a\u00020\u00182\b\b\u0002\u0010\u0010\u001a\u00020\u00062\u0006\u0010\u0012\u001a\u00020\u00112\f\u0010\u0014\u001a\b\u0012\u0004\u0012\u00020\u00020\u00132\f\u0010\u0015\u001a\b\u0012\u0004\u0012\u00020\u00020\u0013¢\u0006\u0004\b\u001a\u0010\u001bJ#\u0010\u001f\u001a\u00020\u00022\u0006\u0010\u001d\u001a\u00020\u001c2\f\u0010\u001e\u001a\b\u0012\u0004\u0012\u00020\u00020\u0013¢\u0006\u0004\b\u001f\u0010 J#\u0010\"\u001a\u00020\u00022\u0006\u0010\u001d\u001a\u00020\u001c2\f\u0010!\u001a\b\u0012\u0004\u0012\u00020\u00020\u0013¢\u0006\u0004\b\"\u0010 J\u001d\u0010%\u001a\u00020\u00022\u0006\u0010\u001d\u001a\u00020\u001c2\u0006\u0010$\u001a\u00020#¢\u0006\u0004\b%\u0010&J\r\u0010'\u001a\u00020\u0002¢\u0006\u0004\b'\u0010\u0004J\r\u0010(\u001a\u00020\b¢\u0006\u0004\b(\u0010)J\r\u0010*\u001a\u00020\b¢\u0006\u0004\b*\u0010)J\r\u0010+\u001a\u00020\b¢\u0006\u0004\b+\u0010)J\u0015\u0010-\u001a\u00020\u00022\u0006\u0010,\u001a\u00020#¢\u0006\u0004\b-\u0010.J\r\u0010/\u001a\u00020\u0006¢\u0006\u0004\b/\u00100J\u0017\u00103\u001a\u00020\u00022\u0006\u00102\u001a\u000201H\u0007¢\u0006\u0004\b3\u00104J\u001d\u00107\u001a\u00020\u00022\u0006\u00106\u001a\u0002052\u0006\u0010$\u001a\u00020#¢\u0006\u0004\b7\u00108J\u0015\u00109\u001a\u00020\u00022\u0006\u0010\u001d\u001a\u00020\u001c¢\u0006\u0004\b9\u0010:J0\u0010A\u001a\u00020\u00022!\u0010@\u001a\u001d\u0012\u0013\u0012\u00110<¢\u0006\f\b=\u0012\b\b>\u0012\u0004\b\b(?\u0012\u0004\u0012\u00020\u00020;¢\u0006\u0004\bA\u0010BJ8\u0010G\u001a\u00020F2\u0006\u0010C\u001a\u00020\u00062!\u0010E\u001a\u001d\u0012\u0013\u0012\u00110\u0006¢\u0006\f\b=\u0012\b\b>\u0012\u0004\b\b(D\u0012\u0004\u0012\u00020\u00020;¢\u0006\u0004\bG\u0010HJ\u000f\u0010I\u001a\u00020\u0002H\u0016¢\u0006\u0004\bI\u0010\u0004J\u0017\u0010K\u001a\u00020\u00022\u0006\u0010J\u001a\u00020\u0006H\u0002¢\u0006\u0004\bK\u0010LJ\u000f\u0010M\u001a\u00020\u0002H\u0002¢\u0006\u0004\bM\u0010\u0004R\u001f\u0010O\u001a\b\u0012\u0004\u0012\u00020#0N8\u0006@\u0006¢\u0006\f\n\u0004\bO\u0010P\u001a\u0004\bQ\u0010RR\u001f\u0010S\u001a\b\u0012\u0004\u0012\u00020#0N8\u0006@\u0006¢\u0006\f\n\u0004\bS\u0010P\u001a\u0004\bT\u0010RR+\u0010E\u001a\u0010\u0012\f\u0012\n U*\u0004\u0018\u00010\b0\b0N8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bV\u0010W\u001a\u0004\bX\u0010RR\u001f\u0010Y\u001a\b\u0012\u0004\u0012\u00020#0N8\u0006@\u0006¢\u0006\f\n\u0004\bY\u0010P\u001a\u0004\bZ\u0010RR\u001f\u0010[\u001a\b\u0012\u0004\u0012\u00020#0N8\u0006@\u0006¢\u0006\f\n\u0004\b[\u0010P\u001a\u0004\b\\\u0010RR\u001f\u0010]\u001a\b\u0012\u0004\u0012\u00020\b0N8\u0006@\u0006¢\u0006\f\n\u0004\b]\u0010P\u001a\u0004\b^\u0010RR\u001f\u0010_\u001a\b\u0012\u0004\u0012\u00020#0N8\u0006@\u0006¢\u0006\f\n\u0004\b_\u0010P\u001a\u0004\b`\u0010RR\u001f\u0010a\u001a\b\u0012\u0004\u0012\u00020#0N8\u0006@\u0006¢\u0006\f\n\u0004\ba\u0010P\u001a\u0004\bb\u0010RR\u001f\u0010c\u001a\b\u0012\u0004\u0012\u00020#0N8\u0006@\u0006¢\u0006\f\n\u0004\bc\u0010P\u001a\u0004\bd\u0010RR\u001f\u0010e\u001a\b\u0012\u0004\u0012\u00020#0N8\u0006@\u0006¢\u0006\f\n\u0004\be\u0010P\u001a\u0004\bf\u0010RR\u001f\u0010g\u001a\b\u0012\u0004\u0012\u00020\u00060N8\u0006@\u0006¢\u0006\f\n\u0004\bg\u0010P\u001a\u0004\bh\u0010RR\u001f\u0010i\u001a\b\u0012\u0004\u0012\u00020#0N8\u0006@\u0006¢\u0006\f\n\u0004\bi\u0010P\u001a\u0004\bj\u0010RR#\u0010n\u001a\b\u0012\u0004\u0012\u00020k0N8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bl\u0010W\u001a\u0004\bm\u0010RR\u001f\u0010o\u001a\b\u0012\u0004\u0012\u00020#0N8\u0006@\u0006¢\u0006\f\n\u0004\bo\u0010P\u001a\u0004\bp\u0010RR\u001f\u0010q\u001a\b\u0012\u0004\u0012\u00020\b0N8\u0006@\u0006¢\u0006\f\n\u0004\bq\u0010P\u001a\u0004\br\u0010RR\u001f\u0010s\u001a\b\u0012\u0004\u0012\u00020#0N8\u0006@\u0006¢\u0006\f\n\u0004\bs\u0010P\u001a\u0004\bt\u0010RR\u001f\u0010u\u001a\b\u0012\u0004\u0012\u00020#0N8\u0006@\u0006¢\u0006\f\n\u0004\bu\u0010P\u001a\u0004\bv\u0010RR#\u0010z\u001a\b\u0012\u0004\u0012\u00020w0N8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bx\u0010W\u001a\u0004\by\u0010RR\u001f\u0010{\u001a\b\u0012\u0004\u0012\u00020#0N8\u0006@\u0006¢\u0006\f\n\u0004\b{\u0010P\u001a\u0004\b|\u0010RR\u001f\u0010}\u001a\b\u0012\u0004\u0012\u00020\b0N8\u0006@\u0006¢\u0006\f\n\u0004\b}\u0010P\u001a\u0004\b~\u0010RR \u0010\u007f\u001a\b\u0012\u0004\u0012\u00020#0N8\u0006@\u0006¢\u0006\r\n\u0004\b\u007f\u0010P\u001a\u0005\b\u0080\u0001\u0010RR\"\u0010\u0081\u0001\u001a\b\u0012\u0004\u0012\u00020#0N8\u0006@\u0006¢\u0006\u000e\n\u0005\b\u0081\u0001\u0010P\u001a\u0005\b\u0082\u0001\u0010RR\"\u0010\u0083\u0001\u001a\b\u0012\u0004\u0012\u00020#0N8\u0006@\u0006¢\u0006\u000e\n\u0005\b\u0083\u0001\u0010P\u001a\u0005\b\u0084\u0001\u0010RR\"\u0010\u0085\u0001\u001a\b\u0012\u0004\u0012\u00020\b0N8\u0006@\u0006¢\u0006\u000e\n\u0005\b\u0085\u0001\u0010P\u001a\u0005\b\u0086\u0001\u0010RR\"\u0010\u0087\u0001\u001a\b\u0012\u0004\u0012\u00020#0N8\u0006@\u0006¢\u0006\u000e\n\u0005\b\u0087\u0001\u0010P\u001a\u0005\b\u0088\u0001\u0010RR\"\u0010\u0089\u0001\u001a\b\u0012\u0004\u0012\u00020#0N8\u0006@\u0006¢\u0006\u000e\n\u0005\b\u0089\u0001\u0010P\u001a\u0005\b\u008a\u0001\u0010RR\u001b\u0010\u008b\u0001\u001a\u0004\u0018\u00010F8\u0002@\u0002X\u0082\u000e¢\u0006\b\n\u0006\b\u008b\u0001\u0010\u008c\u0001R&\u0010\u008f\u0001\u001a\b\u0012\u0004\u0012\u00020\u00180N8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b\u008d\u0001\u0010W\u001a\u0005\b\u008e\u0001\u0010RR\"\u0010\u0090\u0001\u001a\b\u0012\u0004\u0012\u00020#0N8\u0006@\u0006¢\u0006\u000e\n\u0005\b\u0090\u0001\u0010P\u001a\u0005\b\u0091\u0001\u0010RR\"\u0010\u0092\u0001\u001a\b\u0012\u0004\u0012\u00020\u00060N8\u0006@\u0006¢\u0006\u000e\n\u0005\b\u0092\u0001\u0010P\u001a\u0005\b\u0093\u0001\u0010RR\"\u0010\u0094\u0001\u001a\b\u0012\u0004\u0012\u00020#0N8\u0006@\u0006¢\u0006\u000e\n\u0005\b\u0094\u0001\u0010P\u001a\u0005\b\u0095\u0001\u0010RR\u001f\u0010\u0097\u0001\u001a\u00030\u0096\u00018\u0006@\u0006¢\u0006\u0010\n\u0006\b\u0097\u0001\u0010\u0098\u0001\u001a\u0006\b\u0099\u0001\u0010\u009a\u0001¨\u0006\u009c\u0001"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/novel/AudioPlayerViewModel;", "Lcom/qunidayede/supportlibrary/core/viewmodel/BaseViewModel;", "", "onCreate", "()V", "onCleared", "", "chapterId", "", "hasLoading", "novelChapterDetail", "(Ljava/lang/String;Z)V", "chapter_id", "page_at", "loadMusicInfo", "(Ljava/lang/String;ZLjava/lang/String;)V", "url", "Landroid/widget/SeekBar;", "seekBar", "Lkotlin/Function0;", "onMediaPlayerReady", "onCompletion", "prepareMediaPlayertest", "(Ljava/lang/String;Landroid/widget/SeekBar;Lkotlin/jvm/functions/Function0;Lkotlin/jvm/functions/Function0;)V", "Lcom/jbzd/media/movecartoons/bean/response/novel/NovelChapterInfoBean;", "item", "prepareMediaPlayer", "(Lcom/jbzd/media/movecartoons/bean/response/novel/NovelChapterInfoBean;Ljava/lang/String;Landroid/widget/SeekBar;Lkotlin/jvm/functions/Function0;Lkotlin/jvm/functions/Function0;)V", "Landroid/content/Context;", "context", "play", "startPlaybackVM", "(Landroid/content/Context;Lkotlin/jvm/functions/Function0;)V", "pause", "pausePlaybackVM", "", "position", "seekToPositionVM", "(Landroid/content/Context;I)V", "onSwitchButtonClicked", "isFollow", "()Z", "isLove", "isDownload", "currentPosition", "updatePlaybackTime", "(I)V", "getCurrentThemeMode", "()Ljava/lang/String;", "", "speed", "setPlaybackSpeed", "(F)V", "Landroid/app/Activity;", "act", "setPage", "(Landroid/app/Activity;I)V", "playPrev", "(Landroid/content/Context;)V", "Lkotlin/Function1;", "Lcom/jbzd/media/movecartoons/bean/response/novel/NovelChapter;", "Lkotlin/ParameterName;", "name", "c", "cantPlay", "playNext", "(Lkotlin/jvm/functions/Function1;)V", "user_id", "data", FindBean.status_success, "Lc/a/d1;", "follow", "(Ljava/lang/String;Lkotlin/jvm/functions/Function1;)Lc/a/d1;", "onDestroy", "mode", "setThemeMode", "(Ljava/lang/String;)V", "applyThemeMode", "Landroidx/lifecycle/MutableLiveData;", "titleLeftIconLiveData", "Landroidx/lifecycle/MutableLiveData;", "getTitleLeftIconLiveData", "()Landroidx/lifecycle/MutableLiveData;", "playBarPlayPreviousLiveData", "getPlayBarPlayPreviousLiveData", "kotlin.jvm.PlatformType", "success$delegate", "Lkotlin/Lazy;", "getSuccess", "menuLiveData", "getMenuLiveData", "textLiveData", "getTextLiveData", "loadingProgressBar", "getLoadingProgressBar", "timingLiveData", "getTimingLiveData", "switchIconLiveData", "getSwitchIconLiveData", "playBarPlayForwardLiveData", "getPlayBarPlayForwardLiveData", "progressBarLiveData", "getProgressBarLiveData", "mainLrcText", "getMainLrcText", "progressBarLiteLiveData", "getProgressBarLiteLiveData", "Lcom/jbzd/media/movecartoons/bean/response/ChapterInfoBean;", "chapterInfoBeanVM$delegate", "getChapterInfoBeanVM", "chapterInfoBeanVM", "albumLayoutLiveData", "getAlbumLayoutLiveData", "downloadIconLiveData", "getDownloadIconLiveData", "musicViewMaskLiveData", "getMusicViewMaskLiveData", "speedLiveData", "getSpeedLiveData", "Lcom/jbzd/media/movecartoons/bean/response/novel/NovelDetailInfoBean;", "novelDetailInfoBean$delegate", "getNovelDetailInfoBean", "novelDetailInfoBean", "textBlueLiveData", "getTextBlueLiveData", "loveIconLiveData", "getLoveIconLiveData", "playBarPlayNextLiveData", "getPlayBarPlayNextLiveData", "titleRightIconLiveData", "getTitleRightIconLiveData", "playLyricsIconLiveData", "getPlayLyricsIconLiveData", "followIconLiveData", "getFollowIconLiveData", "textLrcNormalLiveData", "getTextLrcNormalLiveData", "playBarBackLiveData", "getPlayBarBackLiveData", "job", "Lc/a/d1;", "novelChapterInfoBean$delegate", "getNovelChapterInfoBean", "novelChapterInfoBean", "playReadModeLiveData", "getPlayReadModeLiveData", "lrcViewDayNightLiveData", "getLrcViewDayNightLiveData", "textLiveData30", "getTextLiveData30", "Lcom/jbzd/media/movecartoons/service/AudioPlayerService;", NotificationCompat.CATEGORY_SERVICE, "Lcom/jbzd/media/movecartoons/service/AudioPlayerService;", "getService", "()Lcom/jbzd/media/movecartoons/service/AudioPlayerService;", "<init>", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class AudioPlayerViewModel extends BaseViewModel {

    @Nullable
    private InterfaceC3053d1 job;

    @NotNull
    private final AudioPlayerService service;

    /* renamed from: success$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy success = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<Boolean>>() { // from class: com.jbzd.media.movecartoons.ui.novel.AudioPlayerViewModel$success$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<Boolean> invoke() {
            return new MutableLiveData<>(Boolean.TRUE);
        }
    });

    /* renamed from: chapterInfoBeanVM$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy chapterInfoBeanVM = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<ChapterInfoBean>>() { // from class: com.jbzd.media.movecartoons.ui.novel.AudioPlayerViewModel$chapterInfoBeanVM$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<ChapterInfoBean> invoke() {
            return new MutableLiveData<>();
        }
    });

    @NotNull
    private final MutableLiveData<Integer> textLiveData = new MutableLiveData<>();

    @NotNull
    private final MutableLiveData<Integer> textLiveData30 = new MutableLiveData<>();

    @NotNull
    private final MutableLiveData<Integer> textBlueLiveData = new MutableLiveData<>();

    @NotNull
    private final MutableLiveData<Integer> textLrcNormalLiveData = new MutableLiveData<>();

    @NotNull
    private final MutableLiveData<Integer> switchIconLiveData = new MutableLiveData<>();

    @NotNull
    private final MutableLiveData<Integer> musicViewMaskLiveData = new MutableLiveData<>();

    @NotNull
    private final MutableLiveData<Integer> titleLeftIconLiveData = new MutableLiveData<>();

    @NotNull
    private final MutableLiveData<Integer> titleRightIconLiveData = new MutableLiveData<>();

    @NotNull
    private final MutableLiveData<Integer> playReadModeLiveData = new MutableLiveData<>();

    @NotNull
    private final MutableLiveData<Integer> timingLiveData = new MutableLiveData<>();

    @NotNull
    private final MutableLiveData<Integer> menuLiveData = new MutableLiveData<>();

    @NotNull
    private final MutableLiveData<Integer> playBarPlayPreviousLiveData = new MutableLiveData<>();

    @NotNull
    private final MutableLiveData<Integer> playBarPlayNextLiveData = new MutableLiveData<>();

    @NotNull
    private final MutableLiveData<Integer> albumLayoutLiveData = new MutableLiveData<>();

    @NotNull
    private final MutableLiveData<Integer> playLyricsIconLiveData = new MutableLiveData<>();

    @NotNull
    private final MutableLiveData<String> lrcViewDayNightLiveData = new MutableLiveData<>();

    @NotNull
    private final MutableLiveData<Boolean> followIconLiveData = new MutableLiveData<>();

    @NotNull
    private final MutableLiveData<Boolean> loveIconLiveData = new MutableLiveData<>();

    @NotNull
    private final MutableLiveData<Boolean> downloadIconLiveData = new MutableLiveData<>();

    @NotNull
    private final MutableLiveData<Integer> speedLiveData = new MutableLiveData<>();

    @NotNull
    private final MutableLiveData<Integer> playBarPlayForwardLiveData = new MutableLiveData<>();

    @NotNull
    private final MutableLiveData<Integer> playBarBackLiveData = new MutableLiveData<>();

    @NotNull
    private final MutableLiveData<Integer> progressBarLiveData = new MutableLiveData<>();

    @NotNull
    private final MutableLiveData<Integer> progressBarLiteLiveData = new MutableLiveData<>();

    @NotNull
    private final MutableLiveData<Boolean> loadingProgressBar = new MutableLiveData<>();

    /* renamed from: novelDetailInfoBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy novelDetailInfoBean = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<NovelDetailInfoBean>>() { // from class: com.jbzd.media.movecartoons.ui.novel.AudioPlayerViewModel$novelDetailInfoBean$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<NovelDetailInfoBean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: novelChapterInfoBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy novelChapterInfoBean = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<NovelChapterInfoBean>>() { // from class: com.jbzd.media.movecartoons.ui.novel.AudioPlayerViewModel$novelChapterInfoBean$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<NovelChapterInfoBean> invoke() {
            return new MutableLiveData<>();
        }
    });

    @NotNull
    private final MutableLiveData<String> mainLrcText = new MutableLiveData<>();

    public AudioPlayerViewModel() {
        if (C0959d0.f570a == null) {
            synchronized (C0959d0.class) {
                if (C0959d0.f570a == null) {
                    C0959d0.f570a = new C0959d0(null);
                }
                Unit unit = Unit.INSTANCE;
            }
        }
        C0959d0 c0959d0 = C0959d0.f570a;
        Intrinsics.checkNotNull(c0959d0);
        this.service = c0959d0.m298a();
    }

    private final void applyThemeMode() {
        String currentThemeMode = getCurrentThemeMode();
        this.lrcViewDayNightLiveData.setValue(currentThemeMode);
        boolean areEqual = Intrinsics.areEqual(currentThemeMode, "day");
        int i2 = R.color.white;
        this.textLiveData.setValue(Integer.valueOf(areEqual ? R.color.black : R.color.white));
        if (Intrinsics.areEqual(currentThemeMode, "day")) {
            i2 = R.color.black30;
        }
        this.textLiveData30.setValue(Integer.valueOf(i2));
    }

    public static /* synthetic */ void loadMusicInfo$default(AudioPlayerViewModel audioPlayerViewModel, String str, boolean z, String str2, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            z = true;
        }
        if ((i2 & 4) != 0) {
            str2 = "";
        }
        audioPlayerViewModel.loadMusicInfo(str, z, str2);
    }

    public static /* synthetic */ void novelChapterDetail$default(AudioPlayerViewModel audioPlayerViewModel, String str, boolean z, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            z = true;
        }
        audioPlayerViewModel.novelChapterDetail(str, z);
    }

    public static /* synthetic */ void prepareMediaPlayer$default(AudioPlayerViewModel audioPlayerViewModel, NovelChapterInfoBean novelChapterInfoBean, String str, SeekBar seekBar, Function0 function0, Function0 function02, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            str = "";
        }
        audioPlayerViewModel.prepareMediaPlayer(novelChapterInfoBean, str, seekBar, function0, function02);
    }

    public static /* synthetic */ void prepareMediaPlayertest$default(AudioPlayerViewModel audioPlayerViewModel, String str, SeekBar seekBar, Function0 function0, Function0 function02, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            str = "";
        }
        audioPlayerViewModel.prepareMediaPlayertest(str, seekBar, function0, function02);
    }

    private final void setThemeMode(String mode) {
        Intrinsics.checkNotNullParameter("theme_mode", "key");
        Intrinsics.checkNotNullParameter(mode, "value");
        ApplicationC2828a applicationC2828a = C2827a.f7670a;
        if (applicationC2828a == null) {
            Intrinsics.throwUninitializedPropertyAccessException("context");
            throw null;
        }
        SharedPreferences sharedPreferences = applicationC2828a.getSharedPreferences("default_storage", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "SupportLibraryInstance.context.getSharedPreferences(DEFAULT_STORAGE_NAME,Context.MODE_PRIVATE)");
        SharedPreferences.Editor editor = sharedPreferences.edit();
        Intrinsics.checkExpressionValueIsNotNull(editor, "editor");
        editor.putString("theme_mode", mode);
        editor.commit();
    }

    @NotNull
    public final InterfaceC3053d1 follow(@NotNull String user_id, @NotNull final Function1<? super String, Unit> success) {
        Intrinsics.checkNotNullParameter(user_id, "user_id");
        Intrinsics.checkNotNullParameter(success, "success");
        C0917a c0917a = C0917a.f372a;
        HashMap m595Q = C1499a.m595Q("user_id", user_id);
        Unit unit = Unit.INSTANCE;
        return C0917a.m221e(c0917a, "user/follow", String.class, m595Q, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.AudioPlayerViewModel$follow$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str) {
                invoke2(str);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str) {
                if (str == null) {
                    return;
                }
                success.invoke(str);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.AudioPlayerViewModel$follow$3
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
            }
        }, false, false, null, false, 480);
    }

    @NotNull
    public final MutableLiveData<Integer> getAlbumLayoutLiveData() {
        return this.albumLayoutLiveData;
    }

    @NotNull
    public final MutableLiveData<ChapterInfoBean> getChapterInfoBeanVM() {
        return (MutableLiveData) this.chapterInfoBeanVM.getValue();
    }

    @NotNull
    public final String getCurrentThemeMode() {
        Intrinsics.checkNotNullParameter("theme_mode", "key");
        Intrinsics.checkNotNullParameter("day", "default");
        ApplicationC2828a applicationC2828a = C2827a.f7670a;
        if (applicationC2828a == null) {
            Intrinsics.throwUninitializedPropertyAccessException("context");
            throw null;
        }
        SharedPreferences sharedPreferences = applicationC2828a.getSharedPreferences("default_storage", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "SupportLibraryInstance.context.getSharedPreferences(DEFAULT_STORAGE_NAME,Context.MODE_PRIVATE)");
        String string = sharedPreferences.getString("theme_mode", "day");
        Intrinsics.checkNotNull(string);
        return string == null ? "day" : string;
    }

    @NotNull
    public final MutableLiveData<Boolean> getDownloadIconLiveData() {
        return this.downloadIconLiveData;
    }

    @NotNull
    public final MutableLiveData<Boolean> getFollowIconLiveData() {
        return this.followIconLiveData;
    }

    @NotNull
    public final MutableLiveData<Boolean> getLoadingProgressBar() {
        return this.loadingProgressBar;
    }

    @NotNull
    public final MutableLiveData<Boolean> getLoveIconLiveData() {
        return this.loveIconLiveData;
    }

    @NotNull
    public final MutableLiveData<String> getLrcViewDayNightLiveData() {
        return this.lrcViewDayNightLiveData;
    }

    @NotNull
    public final MutableLiveData<String> getMainLrcText() {
        return this.mainLrcText;
    }

    @NotNull
    public final MutableLiveData<Integer> getMenuLiveData() {
        return this.menuLiveData;
    }

    @NotNull
    public final MutableLiveData<Integer> getMusicViewMaskLiveData() {
        return this.musicViewMaskLiveData;
    }

    @NotNull
    public final MutableLiveData<NovelChapterInfoBean> getNovelChapterInfoBean() {
        return (MutableLiveData) this.novelChapterInfoBean.getValue();
    }

    @NotNull
    public final MutableLiveData<NovelDetailInfoBean> getNovelDetailInfoBean() {
        return (MutableLiveData) this.novelDetailInfoBean.getValue();
    }

    @NotNull
    public final MutableLiveData<Integer> getPlayBarBackLiveData() {
        return this.playBarBackLiveData;
    }

    @NotNull
    public final MutableLiveData<Integer> getPlayBarPlayForwardLiveData() {
        return this.playBarPlayForwardLiveData;
    }

    @NotNull
    public final MutableLiveData<Integer> getPlayBarPlayNextLiveData() {
        return this.playBarPlayNextLiveData;
    }

    @NotNull
    public final MutableLiveData<Integer> getPlayBarPlayPreviousLiveData() {
        return this.playBarPlayPreviousLiveData;
    }

    @NotNull
    public final MutableLiveData<Integer> getPlayLyricsIconLiveData() {
        return this.playLyricsIconLiveData;
    }

    @NotNull
    public final MutableLiveData<Integer> getPlayReadModeLiveData() {
        return this.playReadModeLiveData;
    }

    @NotNull
    public final MutableLiveData<Integer> getProgressBarLiteLiveData() {
        return this.progressBarLiteLiveData;
    }

    @NotNull
    public final MutableLiveData<Integer> getProgressBarLiveData() {
        return this.progressBarLiveData;
    }

    @NotNull
    public final AudioPlayerService getService() {
        return this.service;
    }

    @NotNull
    public final MutableLiveData<Integer> getSpeedLiveData() {
        return this.speedLiveData;
    }

    @NotNull
    public final MutableLiveData<Boolean> getSuccess() {
        return (MutableLiveData) this.success.getValue();
    }

    @NotNull
    public final MutableLiveData<Integer> getSwitchIconLiveData() {
        return this.switchIconLiveData;
    }

    @NotNull
    public final MutableLiveData<Integer> getTextBlueLiveData() {
        return this.textBlueLiveData;
    }

    @NotNull
    public final MutableLiveData<Integer> getTextLiveData() {
        return this.textLiveData;
    }

    @NotNull
    public final MutableLiveData<Integer> getTextLiveData30() {
        return this.textLiveData30;
    }

    @NotNull
    public final MutableLiveData<Integer> getTextLrcNormalLiveData() {
        return this.textLrcNormalLiveData;
    }

    @NotNull
    public final MutableLiveData<Integer> getTimingLiveData() {
        return this.timingLiveData;
    }

    @NotNull
    public final MutableLiveData<Integer> getTitleLeftIconLiveData() {
        return this.titleLeftIconLiveData;
    }

    @NotNull
    public final MutableLiveData<Integer> getTitleRightIconLiveData() {
        return this.titleRightIconLiveData;
    }

    public final boolean isDownload() {
        Boolean value = this.downloadIconLiveData.getValue();
        if (value == null) {
            return false;
        }
        return value.booleanValue();
    }

    public final boolean isFollow() {
        Boolean value = this.followIconLiveData.getValue();
        if (value == null) {
            return false;
        }
        return value.booleanValue();
    }

    public final boolean isLove() {
        Boolean value = this.loveIconLiveData.getValue();
        if (value == null) {
            return false;
        }
        return value.booleanValue();
    }

    public final void loadMusicInfo(@NotNull String chapter_id, boolean hasLoading, @NotNull String page_at) {
        Intrinsics.checkNotNullParameter(chapter_id, "chapter_id");
        Intrinsics.checkNotNullParameter(page_at, "page_at");
        if (hasLoading) {
            this.loadingProgressBar.setValue(Boolean.TRUE);
        }
        if (page_at.length() == 0) {
            page_at = String.valueOf(getService().pageAt);
        }
        HashMap m596R = C1499a.m596R("chapter_id", chapter_id, "page", page_at);
        Unit unit = Unit.INSTANCE;
        this.job = C0917a.m221e(C0917a.f372a, "book/chapterInfo", ChapterInfoBean.class, m596R, new Function1<ChapterInfoBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.AudioPlayerViewModel$loadMusicInfo$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ChapterInfoBean chapterInfoBean) {
                invoke2(chapterInfoBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable ChapterInfoBean chapterInfoBean) {
                InfoBean info;
                MutableLiveData<Boolean> loadingProgressBar = AudioPlayerViewModel.this.getLoadingProgressBar();
                Boolean bool = Boolean.FALSE;
                loadingProgressBar.setValue(bool);
                String str = null;
                if (chapterInfoBean != null && (info = chapterInfoBean.getInfo()) != null) {
                    str = info.getLink();
                }
                if (Intrinsics.areEqual(str, "")) {
                    C2354n.m2449Z("无效音源请确认");
                    AudioPlayerViewModel.this.getSuccess().setValue(bool);
                } else {
                    AudioPlayerViewModel.this.getService().m4201c().setValue(chapterInfoBean);
                    AudioPlayerViewModel.this.getSuccess().setValue(Boolean.TRUE);
                }
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.AudioPlayerViewModel$loadMusicInfo$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                MutableLiveData<Boolean> loadingProgressBar = AudioPlayerViewModel.this.getLoadingProgressBar();
                Boolean bool = Boolean.FALSE;
                loadingProgressBar.setValue(bool);
                AudioPlayerViewModel.this.getSuccess().setValue(bool);
            }
        }, false, false, null, false, 480);
    }

    public final void novelChapterDetail(@NotNull String chapterId, final boolean hasLoading) {
        Intrinsics.checkNotNullParameter(chapterId, "chapterId");
        if (hasLoading) {
            getLoading().setValue(new C2848a(true, null, false, false, 14));
        }
        HashMap hashMap = new HashMap();
        hashMap.put("id", chapterId);
        this.job = C0917a.m221e(C0917a.f372a, "novel/chapterDetail", NovelChapterInfoBean.class, hashMap, new Function1<NovelChapterInfoBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.AudioPlayerViewModel$novelChapterDetail$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(NovelChapterInfoBean novelChapterInfoBean) {
                invoke2(novelChapterInfoBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable NovelChapterInfoBean novelChapterInfoBean) {
                AudioPlayerViewModel.this.getNovelChapterInfoBean().setValue(novelChapterInfoBean);
                AudioPlayerViewModel.this.getService().m4202d().setValue(novelChapterInfoBean);
                AudioPlayerViewModel.this.getService().m4203e().setValue(AudioPlayerViewModel.this.getNovelDetailInfoBean().getValue());
                if (hasLoading) {
                    AudioPlayerViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.AudioPlayerViewModel$novelChapterDetail$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
            }
        }, false, false, null, false, 480);
    }

    @Override // androidx.lifecycle.ViewModel
    public void onCleared() {
        super.onCleared();
        this.service.stopSelf();
    }

    @Override // com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel
    public void onCreate() {
        applyThemeMode();
    }

    @Override // com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel
    public void onDestroy() {
        super.onDestroy();
        cancelJob(this.job);
    }

    public final void onSwitchButtonClicked() {
        setThemeMode(Intrinsics.areEqual(getCurrentThemeMode(), "day") ? "night" : "day");
        applyThemeMode();
    }

    public final void pausePlaybackVM(@NotNull Context context, @NotNull Function0<Unit> pause) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(pause, "pause");
        this.service.m4220v(false);
        this.service.m4207i(context, pause);
    }

    public final void playNext(@NotNull final Function1<? super NovelChapter, Unit> cantPlay) {
        Intrinsics.checkNotNullParameter(cantPlay, "cantPlay");
        this.service.m4208j(new Function1<NovelChapter, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.AudioPlayerViewModel$playNext$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(NovelChapter novelChapter) {
                invoke2(novelChapter);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull NovelChapter it) {
                Intrinsics.checkNotNullParameter(it, "it");
                AudioPlayerViewModel.novelChapterDetail$default(AudioPlayerViewModel.this, it.f10026id.toString(), false, 2, null);
            }
        }, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.AudioPlayerViewModel$playNext$2
            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
                C2354n.m2525w0("没有下一章");
            }
        }, new Function1<NovelChapter, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.AudioPlayerViewModel$playNext$3
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(NovelChapter novelChapter) {
                invoke2(novelChapter);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull NovelChapter it) {
                Intrinsics.checkNotNullParameter(it, "it");
                cantPlay.invoke(it);
            }
        });
    }

    public final void playPrev(@NotNull final Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.service.m4209k(new Function1<NovelChapter, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.AudioPlayerViewModel$playPrev$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(NovelChapter novelChapter) {
                invoke2(novelChapter);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull NovelChapter it) {
                Intrinsics.checkNotNullParameter(it, "it");
                AudioPlayerViewModel.novelChapterDetail$default(AudioPlayerViewModel.this, it.f10026id.toString(), false, 2, null);
            }
        }, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.AudioPlayerViewModel$playPrev$2
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
                AudioPlayerViewModel.this.seekToPositionVM(context, 0);
                C2354n.m2525w0("没有上一章");
            }
        });
    }

    public final void prepareMediaPlayer(@NotNull NovelChapterInfoBean item, @NotNull String url, @NotNull SeekBar seekBar, @NotNull Function0<Unit> onMediaPlayerReady, @NotNull Function0<Unit> onCompletion) {
        Intrinsics.checkNotNullParameter(item, "item");
        Intrinsics.checkNotNullParameter(url, "url");
        Intrinsics.checkNotNullParameter(seekBar, "seekBar");
        Intrinsics.checkNotNullParameter(onMediaPlayerReady, "onMediaPlayerReady");
        Intrinsics.checkNotNullParameter(onCompletion, "onCompletion");
        C2354n.m2435U0(ViewModelKt.getViewModelScope(this), null, 0, new AudioPlayerViewModel$prepareMediaPlayer$1(url, seekBar, this, onMediaPlayerReady, item, onCompletion, null), 3, null);
    }

    public final void prepareMediaPlayertest(@NotNull String url, @NotNull SeekBar seekBar, @NotNull Function0<Unit> onMediaPlayerReady, @NotNull Function0<Unit> onCompletion) {
        Intrinsics.checkNotNullParameter(url, "url");
        Intrinsics.checkNotNullParameter(seekBar, "seekBar");
        Intrinsics.checkNotNullParameter(onMediaPlayerReady, "onMediaPlayerReady");
        Intrinsics.checkNotNullParameter(onCompletion, "onCompletion");
        C2354n.m2435U0(ViewModelKt.getViewModelScope(this), null, 0, new AudioPlayerViewModel$prepareMediaPlayertest$1(url, this, onMediaPlayerReady, onCompletion, null), 3, null);
    }

    public final void seekToPositionVM(@NotNull Context context, int position) {
        Intrinsics.checkNotNullParameter(context, "context");
        AudioPlayerService audioPlayerService = this.service;
        AudioPlayerViewModel$seekToPositionVM$1 seekToPosition = new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.AudioPlayerViewModel$seekToPositionVM$1
            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
            }
        };
        Objects.requireNonNull(audioPlayerService);
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(seekToPosition, "seekToPosition");
        audioPlayerService.mediaPlayer.seekTo(position);
        audioPlayerService.currentPosition.setValue(Integer.valueOf(position));
        seekToPosition.invoke();
        LocalBroadcastManager localBroadcastManager = LocalBroadcastManager.getInstance(context);
        Intent intent = new Intent("MUSIC_SERVICE_ACTION");
        intent.putExtra("progress", position);
        Unit unit = Unit.INSTANCE;
        localBroadcastManager.sendBroadcast(intent);
    }

    public final void setPage(@NotNull Activity act, int position) {
        Intrinsics.checkNotNullParameter(act, "act");
        AudioPlayerActivity audioPlayerActivity = act instanceof AudioPlayerActivity ? (AudioPlayerActivity) act : null;
        if (audioPlayerActivity == null) {
            return;
        }
        audioPlayerActivity.setCurrentItem(position);
    }

    @RequiresApi(23)
    public final void setPlaybackSpeed(float speed) {
        PlaybackParams playbackParams = new PlaybackParams();
        playbackParams.setSpeed(speed);
        if (this.service.mediaPlayer.isPlaying()) {
            this.service.mediaPlayer.setPlaybackParams(playbackParams);
        } else {
            this.service.mediaPlayer.setPlaybackParams(playbackParams);
            this.service.mediaPlayer.pause();
        }
    }

    public final void startPlaybackVM(@NotNull Context context, @NotNull Function0<Unit> play) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(play, "play");
        this.service.m4216r(context, play);
    }

    public final void updatePlaybackTime(int currentPosition) {
        int i2 = currentPosition / 1000;
        StringCompanionObject stringCompanionObject = StringCompanionObject.INSTANCE;
        String format = String.format("%02d:%02d", Arrays.copyOf(new Object[]{Integer.valueOf(i2 / 60), Integer.valueOf(i2 % 60)}, 2));
        Intrinsics.checkNotNullExpressionValue(format, "format(format, *args)");
        this.service.startTime.setValue(format);
    }
}

package com.jbzd.media.movecartoons.p396ui.movie;

import android.content.SharedPreferences;
import androidx.lifecycle.MutableLiveData;
import com.jbzd.media.movecartoons.bean.event.EventSubscription;
import com.jbzd.media.movecartoons.bean.response.BuySuccessBean;
import com.jbzd.media.movecartoons.bean.response.DownloadVideoInfo;
import com.jbzd.media.movecartoons.bean.response.FindBean;
import com.jbzd.media.movecartoons.bean.response.VideoDetailBean;
import com.jbzd.media.movecartoons.p396ui.index.home.HomeDataHelper;
import com.jbzd.media.movecartoons.p396ui.mine.MineViewModel;
import com.luck.picture.lib.config.PictureConfig;
import com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;
import java.util.Timer;
import java.util.TimerTask;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Ref;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0855k0;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.p146l.C1568e;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p325v.p326a.C2818e;
import p005b.p327w.p330b.C2827a;
import p005b.p327w.p330b.p331b.ApplicationC2828a;
import p005b.p327w.p330b.p331b.p335f.C2848a;
import p379c.p380a.InterfaceC3053d1;
import p476m.p496b.p497a.C4909c;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000h\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0013\n\u0002\u0010\b\n\u0002\b\n\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u000f\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u000e\n\u0002\u0010\t\n\u0002\b(\u0018\u00002\u00020\u0001B\b¢\u0006\u0005\b\u008a\u0001\u0010\u000eJ8\u0010\u000b\u001a\u00020\t2\u0006\u0010\u0003\u001a\u00020\u00022!\u0010\n\u001a\u001d\u0012\u0013\u0012\u00110\u0005¢\u0006\f\b\u0006\u0012\b\b\u0007\u0012\u0004\b\b(\b\u0012\u0004\u0012\u00020\t0\u0004¢\u0006\u0004\b\u000b\u0010\fJ\r\u0010\r\u001a\u00020\t¢\u0006\u0004\b\r\u0010\u000eJ\u0015\u0010\u0010\u001a\u00020\t2\u0006\u0010\u000f\u001a\u00020\u0002¢\u0006\u0004\b\u0010\u0010\u0011J\u0015\u0010\u0013\u001a\u00020\t2\u0006\u0010\u0012\u001a\u00020\u0002¢\u0006\u0004\b\u0013\u0010\u0011J\u0015\u0010\u0015\u001a\u00020\t2\u0006\u0010\u0014\u001a\u00020\u0005¢\u0006\u0004\b\u0015\u0010\u0016J\u0015\u0010\u0018\u001a\u00020\t2\u0006\u0010\u0017\u001a\u00020\u0005¢\u0006\u0004\b\u0018\u0010\u0016J\u0015\u0010\u001a\u001a\u00020\t2\u0006\u0010\u0019\u001a\u00020\u0005¢\u0006\u0004\b\u001a\u0010\u0016J\u0015\u0010\u001c\u001a\u00020\t2\u0006\u0010\u001b\u001a\u00020\u0005¢\u0006\u0004\b\u001c\u0010\u0016J\u0015\u0010\u001f\u001a\u00020\t2\u0006\u0010\u001e\u001a\u00020\u001d¢\u0006\u0004\b\u001f\u0010 J\u000f\u0010!\u001a\u00020\tH\u0016¢\u0006\u0004\b!\u0010\u000eJ\u001f\u0010#\u001a\u00020\t2\b\u0010\u0003\u001a\u0004\u0018\u00010\u00022\u0006\u0010\"\u001a\u00020\u0002¢\u0006\u0004\b#\u0010$J\u0015\u0010&\u001a\u00020\t2\u0006\u0010%\u001a\u00020\u001d¢\u0006\u0004\b&\u0010 J\r\u0010'\u001a\u00020\t¢\u0006\u0004\b'\u0010\u000eJe\u0010.\u001a\u00020\t2\u0006\u0010\u0003\u001a\u00020\u00022%\b\u0002\u0010\n\u001a\u001f\u0012\u0015\u0012\u0013\u0018\u00010(¢\u0006\f\b\u0006\u0012\b\b\u0007\u0012\u0004\b\b()\u0012\u0004\u0012\u00020\t0\u00042'\b\u0002\u0010-\u001a!\u0012\u0017\u0012\u00150*j\u0002`+¢\u0006\f\b\u0006\u0012\b\b\u0007\u0012\u0004\b\b(,\u0012\u0004\u0012\u00020\t0\u0004¢\u0006\u0004\b.\u0010/Jm\u00101\u001a\u00020\t2\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u00100\u001a\u00020\u00022%\b\u0002\u0010\n\u001a\u001f\u0012\u0015\u0012\u0013\u0018\u00010(¢\u0006\f\b\u0006\u0012\b\b\u0007\u0012\u0004\b\b()\u0012\u0004\u0012\u00020\t0\u00042'\b\u0002\u0010-\u001a!\u0012\u0017\u0012\u00150*j\u0002`+¢\u0006\f\b\u0006\u0012\b\b\u0007\u0012\u0004\b\b(,\u0012\u0004\u0012\u00020\t0\u0004¢\u0006\u0004\b1\u00102Jc\u00103\u001a\u00020\t2\u0006\u0010\u0003\u001a\u00020\u00022#\u0010\n\u001a\u001f\u0012\u0015\u0012\u0013\u0018\u00010(¢\u0006\f\b\u0006\u0012\b\b\u0007\u0012\u0004\b\b()\u0012\u0004\u0012\u00020\t0\u00042'\b\u0002\u0010-\u001a!\u0012\u0017\u0012\u00150*j\u0002`+¢\u0006\f\b\u0006\u0012\b\b\u0007\u0012\u0004\b\b(,\u0012\u0004\u0012\u00020\t0\u0004¢\u0006\u0004\b3\u0010/J\u001f\u00105\u001a\u00020\t2\u0006\u0010\u0003\u001a\u00020\u00022\b\b\u0002\u00104\u001a\u00020\u0005¢\u0006\u0004\b5\u00106J\u0017\u00107\u001a\u00020\t2\b\u0010\u0003\u001a\u0004\u0018\u00010\u0002¢\u0006\u0004\b7\u0010\u0011J!\u0010:\u001a\u00020\t2\b\u00108\u001a\u0004\u0018\u00010\u00022\b\b\u0002\u00109\u001a\u00020\u0005¢\u0006\u0004\b:\u00106R#\u0010@\u001a\b\u0012\u0004\u0012\u00020\u00050;8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b<\u0010=\u001a\u0004\b>\u0010?R#\u0010D\u001a\b\u0012\u0004\u0012\u00020A0;8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bB\u0010=\u001a\u0004\bC\u0010?R#\u0010G\u001a\b\u0012\u0004\u0012\u00020\u00050;8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bE\u0010=\u001a\u0004\bF\u0010?R#\u0010J\u001a\b\u0012\u0004\u0012\u00020\u00020;8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bH\u0010=\u001a\u0004\bI\u0010?R\u0018\u0010L\u001a\u0004\u0018\u00010K8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\bL\u0010MR#\u0010P\u001a\b\u0012\u0004\u0012\u00020\u00050;8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bN\u0010=\u001a\u0004\bO\u0010?R#\u0010S\u001a\b\u0012\u0004\u0012\u00020\u00020;8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bQ\u0010=\u001a\u0004\bR\u0010?R\"\u0010U\u001a\u00020T8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\bU\u0010V\u001a\u0004\bW\u0010X\"\u0004\bY\u0010ZR#\u0010\u0012\u001a\b\u0012\u0004\u0012\u00020\u00020;8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b[\u0010=\u001a\u0004\b\\\u0010?R#\u0010_\u001a\b\u0012\u0004\u0012\u00020\u00020;8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b]\u0010=\u001a\u0004\b^\u0010?R#\u0010b\u001a\b\u0012\u0004\u0012\u00020\u00050;8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b`\u0010=\u001a\u0004\ba\u0010?R#\u0010f\u001a\b\u0012\u0004\u0012\u00020c0;8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bd\u0010=\u001a\u0004\be\u0010?R#\u0010i\u001a\b\u0012\u0004\u0012\u00020\u00020;8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bg\u0010=\u001a\u0004\bh\u0010?R#\u0010l\u001a\b\u0012\u0004\u0012\u00020\u00020;8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bj\u0010=\u001a\u0004\bk\u0010?R#\u0010o\u001a\b\u0012\u0004\u0012\u00020\u00020;8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bm\u0010=\u001a\u0004\bn\u0010?R#\u0010r\u001a\b\u0012\u0004\u0012\u00020\u00050;8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bp\u0010=\u001a\u0004\bq\u0010?R\"\u0010s\u001a\u00020\u00058\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\bs\u0010t\u001a\u0004\bu\u0010v\"\u0004\bw\u0010\u0016R#\u0010z\u001a\b\u0012\u0004\u0012\u00020\u00050;8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bx\u0010=\u001a\u0004\by\u0010?R#\u0010}\u001a\b\u0012\u0004\u0012\u00020\u00020;8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b{\u0010=\u001a\u0004\b|\u0010?R$\u0010\u0080\u0001\u001a\b\u0012\u0004\u0012\u00020\u00050;8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b~\u0010=\u001a\u0004\b\u007f\u0010?R&\u0010\u0083\u0001\u001a\b\u0012\u0004\u0012\u00020\u001d0;8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b\u0081\u0001\u0010=\u001a\u0005\b\u0082\u0001\u0010?R&\u0010\u0086\u0001\u001a\b\u0012\u0004\u0012\u00020\u00050;8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b\u0084\u0001\u0010=\u001a\u0005\b\u0085\u0001\u0010?R&\u0010\u0089\u0001\u001a\b\u0012\u0004\u0012\u00020\u00050;8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b\u0087\u0001\u0010=\u001a\u0005\b\u0088\u0001\u0010?¨\u0006\u008b\u0001"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/movie/MovieDetailsViewModel;", "Lcom/qunidayede/supportlibrary/core/viewmodel/BaseViewModel;", "", "id", "Lkotlin/Function1;", "", "Lkotlin/ParameterName;", "name", "bool", "", FindBean.status_success, "userDoFollow", "(Ljava/lang/String;Lkotlin/jvm/functions/Function1;)V", "updateLine", "()V", "linkUrl", "setLink", "(Ljava/lang/String;)V", "linkName", "setLinkName", "hasLove", "updateLoveNum", "(Z)V", "hasDisLike", "updateUnlikeUnm", "hasLike", "updateZanNum", "hasFollow", "updateFollow", "", PictureConfig.EXTRA_DATA_COUNT, "updateCountdown", "(I)V", "onCreate", "link_id", "loadMovie", "(Ljava/lang/String;Ljava/lang/String;)V", "time", "computerCountDown", "downLoad", "", "response", "Ljava/lang/Exception;", "Lkotlin/Exception;", C1568e.f1949a, "error", "doFavorite", "(Ljava/lang/String;Lkotlin/jvm/functions/Function1;Lkotlin/jvm/functions/Function1;)V", "islike", "doZan", "(Ljava/lang/String;Ljava/lang/String;Lkotlin/jvm/functions/Function1;Lkotlin/jvm/functions/Function1;)V", "doFollow", "needLoading", "doBuyMovie", "(Ljava/lang/String;Z)V", "addHistory", "userId", "hasLoading", "doCollect", "Landroidx/lifecycle/MutableLiveData;", "collect$delegate", "Lkotlin/Lazy;", "getCollect", "()Landroidx/lifecycle/MutableLiveData;", "collect", "Lcom/jbzd/media/movecartoons/bean/response/VideoDetailBean;", "detailInfo$delegate", "getDetailInfo", "detailInfo", "mHasZan$delegate", "getMHasZan", "mHasZan", "linkId$delegate", "getLinkId", "linkId", "Lc/a/d1;", "job", "Lc/a/d1;", "mHasFavorite$delegate", "getMHasFavorite", "mHasFavorite", "mLoveNum$delegate", "getMLoveNum", "mLoveNum", "Ljava/util/Timer;", "timeCount", "Ljava/util/Timer;", "getTimeCount", "()Ljava/util/Timer;", "setTimeCount", "(Ljava/util/Timer;)V", "linkName$delegate", "getLinkName", "downloading$delegate", "getDownloading", "downloading", "mHasHate$delegate", "getMHasHate", "mHasHate", "", "duration$delegate", "getDuration", "duration", "linkCur$delegate", "getLinkCur", "linkCur", "mZanNum$delegate", "getMZanNum", "mZanNum", "mFavoriteNum$delegate", "getMFavoriteNum", "mFavoriteNum", "alreadyTag$delegate", "getAlreadyTag", "alreadyTag", "hasAddHistory", "Z", "getHasAddHistory", "()Z", "setHasAddHistory", "showPlayError$delegate", "getShowPlayError", "showPlayError", "linkIdMulti$delegate", "getLinkIdMulti", "linkIdMulti", "headerPlay$delegate", "getHeaderPlay", "headerPlay", "countdown$delegate", "getCountdown", "countdown", "showError$delegate", "getShowError", "showError", "mHasFolllow$delegate", "getMHasFolllow", "mHasFolllow", "<init>", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class MovieDetailsViewModel extends BaseViewModel {
    private boolean hasAddHistory;

    @Nullable
    private InterfaceC3053d1 job;

    /* renamed from: detailInfo$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy detailInfo = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<VideoDetailBean>>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsViewModel$detailInfo$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<VideoDetailBean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: alreadyTag$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy alreadyTag = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<Boolean>>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsViewModel$alreadyTag$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<Boolean> invoke() {
            return new MutableLiveData<>(Boolean.FALSE);
        }
    });

    /* renamed from: countdown$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy countdown = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<Integer>>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsViewModel$countdown$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<Integer> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: duration$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy duration = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<Long>>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsViewModel$duration$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<Long> invoke() {
            return new MutableLiveData<>(0L);
        }
    });

    /* renamed from: linkCur$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy linkCur = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<String>>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsViewModel$linkCur$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<String> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: linkName$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy linkName = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<String>>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsViewModel$linkName$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<String> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: linkId$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy linkId = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<String>>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsViewModel$linkId$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<String> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: linkIdMulti$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy linkIdMulti = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<String>>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsViewModel$linkIdMulti$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<String> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: mHasFavorite$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mHasFavorite = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<Boolean>>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsViewModel$mHasFavorite$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<Boolean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: mHasZan$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mHasZan = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<Boolean>>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsViewModel$mHasZan$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<Boolean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: mHasHate$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mHasHate = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<Boolean>>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsViewModel$mHasHate$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<Boolean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: mHasFolllow$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mHasFolllow = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<Boolean>>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsViewModel$mHasFolllow$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<Boolean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: mLoveNum$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mLoveNum = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<String>>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsViewModel$mLoveNum$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<String> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: mFavoriteNum$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mFavoriteNum = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<String>>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsViewModel$mFavoriteNum$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<String> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: mZanNum$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mZanNum = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<String>>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsViewModel$mZanNum$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<String> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: collect$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy collect = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<Boolean>>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsViewModel$collect$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<Boolean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: showError$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy showError = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<Boolean>>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsViewModel$showError$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<Boolean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: showPlayError$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy showPlayError = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<Boolean>>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsViewModel$showPlayError$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<Boolean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: downloading$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy downloading = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<String>>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsViewModel$downloading$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<String> invoke() {
            return new MutableLiveData<>("");
        }
    });

    /* renamed from: headerPlay$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy headerPlay = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<Boolean>>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsViewModel$headerPlay$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<Boolean> invoke() {
            return new MutableLiveData<>();
        }
    });

    @NotNull
    private Timer timeCount = new Timer();

    public static /* synthetic */ void doBuyMovie$default(MovieDetailsViewModel movieDetailsViewModel, String str, boolean z, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            z = false;
        }
        movieDetailsViewModel.doBuyMovie(str, z);
    }

    public static /* synthetic */ void doCollect$default(MovieDetailsViewModel movieDetailsViewModel, String str, boolean z, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            z = true;
        }
        movieDetailsViewModel.doCollect(str, z);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ void doFavorite$default(MovieDetailsViewModel movieDetailsViewModel, String str, Function1 function1, Function1 function12, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            function1 = new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsViewModel$doFavorite$1
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Object obj2) {
                    invoke2(obj2);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@Nullable Object obj2) {
                }
            };
        }
        if ((i2 & 4) != 0) {
            function12 = new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsViewModel$doFavorite$2
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                    invoke2(exc);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull Exception it) {
                    Intrinsics.checkNotNullParameter(it, "it");
                }
            };
        }
        movieDetailsViewModel.doFavorite(str, function1, function12);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ void doFollow$default(MovieDetailsViewModel movieDetailsViewModel, String str, Function1 function1, Function1 function12, int i2, Object obj) {
        if ((i2 & 4) != 0) {
            function12 = new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsViewModel$doFollow$1
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                    invoke2(exc);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull Exception it) {
                    Intrinsics.checkNotNullParameter(it, "it");
                }
            };
        }
        movieDetailsViewModel.doFollow(str, function1, function12);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ void doZan$default(MovieDetailsViewModel movieDetailsViewModel, String str, String str2, Function1 function1, Function1 function12, int i2, Object obj) {
        if ((i2 & 4) != 0) {
            function1 = new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsViewModel$doZan$1
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Object obj2) {
                    invoke2(obj2);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@Nullable Object obj2) {
                }
            };
        }
        if ((i2 & 8) != 0) {
            function12 = new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsViewModel$doZan$2
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                    invoke2(exc);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull Exception it) {
                    Intrinsics.checkNotNullParameter(it, "it");
                }
            };
        }
        movieDetailsViewModel.doZan(str, str2, function1, function12);
    }

    public final void addHistory(@Nullable String id) {
        if ((id == null || id.length() == 0) || getDetailInfo().getValue() == null) {
            return;
        }
        HashMap m595Q = C1499a.m595Q("id", id);
        Long value = getDuration().getValue();
        Intrinsics.checkNotNull(value);
        m595Q.put("time", String.valueOf(value.longValue() / 1000));
        C0917a.m221e(C0917a.f372a, "movie/doHistory", String.class, m595Q, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsViewModel$addHistory$1$2
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
                C2818e.m3272a(Intrinsics.stringPlus("添加历史成功:", MovieDetailsViewModel.this.getDuration().getValue()), new Object[0]);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsViewModel$addHistory$1$3
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
            }
        }, false, false, null, false, 416);
    }

    public final void computerCountDown(final int time) {
        if (time < 0) {
            return;
        }
        final Ref.IntRef intRef = new Ref.IntRef();
        intRef.element = time;
        this.timeCount.schedule(new TimerTask() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsViewModel$computerCountDown$1
            @Override // java.util.TimerTask, java.lang.Runnable
            public void run() {
                Ref.IntRef intRef2 = Ref.IntRef.this;
                intRef2.element--;
                this.getCountdown().postValue(Integer.valueOf(Ref.IntRef.this.element));
                if (time < 0) {
                    this.getTimeCount().cancel();
                }
            }
        }, 0L, 1000L);
    }

    public final void doBuyMovie(@NotNull final String id, boolean needLoading) {
        Intrinsics.checkNotNullParameter(id, "id");
        if (needLoading) {
            getLoading().setValue(new C2848a(true, null, false, false, 14));
        }
        C0917a c0917a = C0917a.f372a;
        HashMap m595Q = C1499a.m595Q("id", id);
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "movie/doBuy", BuySuccessBean.class, m595Q, new Function1<BuySuccessBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsViewModel$doBuyMovie$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(BuySuccessBean buySuccessBean) {
                invoke2(buySuccessBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable BuySuccessBean buySuccessBean) {
                MovieDetailsViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                MineViewModel.INSTANCE.getUserInfo();
                C2354n.m2409L1("购买成功");
                MovieDetailsViewModel.this.loadMovie(id, "");
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsViewModel$doBuyMovie$3
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
                C2354n.m2409L1("购买失败");
                MovieDetailsViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
            }
        }, false, false, null, false, 480);
    }

    public final void doCollect(@Nullable String userId, final boolean hasLoading) {
        HomeDataHelper.INSTANCE.doFollow(userId, new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsViewModel$doCollect$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Object obj) {
                invoke2(obj);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable Object obj) {
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
                this.getCollect().setValue(Boolean.TRUE);
                C4909c.m5569b().m5574g(new EventSubscription());
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsViewModel$doCollect$2
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
                MovieDetailsViewModel.this.getCollect().setValue(Boolean.FALSE);
            }
        });
    }

    public final void doFavorite(@NotNull String id, @NotNull Function1<Object, Unit> success, @NotNull Function1<? super Exception, Unit> error) {
        Intrinsics.checkNotNullParameter(id, "id");
        Intrinsics.checkNotNullParameter(success, "success");
        Intrinsics.checkNotNullParameter(error, "error");
        HomeDataHelper.INSTANCE.doLove(id, "1", "long", success, error);
    }

    public final void doFollow(@NotNull String id, @NotNull Function1<Object, Unit> success, @NotNull Function1<? super Exception, Unit> error) {
        Intrinsics.checkNotNullParameter(id, "id");
        Intrinsics.checkNotNullParameter(success, "success");
        Intrinsics.checkNotNullParameter(error, "error");
        C0917a c0917a = C0917a.f372a;
        HashMap m595Q = C1499a.m595Q("home_id", id);
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "video/favoriteAnchor", Object.class, m595Q, success, error, false, false, null, false, 480);
    }

    public final void doZan(@NotNull String id, @NotNull String islike, @NotNull Function1<Object, Unit> success, @NotNull Function1<? super Exception, Unit> error) {
        Intrinsics.checkNotNullParameter(id, "id");
        Intrinsics.checkNotNullParameter(islike, "islike");
        Intrinsics.checkNotNullParameter(success, "success");
        Intrinsics.checkNotNullParameter(error, "error");
        HomeDataHelper.INSTANCE.doZan(id, islike, success, error);
    }

    public final void downLoad() {
        VideoDetailBean value = getDetailInfo().getValue();
        if (value == null) {
            return;
        }
        getDownloading().setValue("");
        getLoading().setValue(new C2848a(true, null, false, false, 14));
        C0917a c0917a = C0917a.f372a;
        HashMap hashMap = new HashMap();
        hashMap.put("id", value.f10000id);
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "movie/doDownload", DownloadVideoInfo.class, hashMap, new Function1<DownloadVideoInfo, Unit>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsViewModel$downLoad$1$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(DownloadVideoInfo downloadVideoInfo) {
                invoke2(downloadVideoInfo);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable DownloadVideoInfo downloadVideoInfo) {
                MovieDetailsViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                MutableLiveData<String> downloading = MovieDetailsViewModel.this.getDownloading();
                VideoDetailBean value2 = MovieDetailsViewModel.this.getDetailInfo().getValue();
                Intrinsics.checkNotNull(value2);
                downloading.setValue(value2.f10000id);
                if (downloadVideoInfo == null) {
                    return;
                }
                VideoDetailBean value3 = MovieDetailsViewModel.this.getDetailInfo().getValue();
                Intrinsics.checkNotNull(value3);
                downloadVideoInfo.f9947id = value3.f10000id;
                Objects.requireNonNull(C0855k0.f257a);
                C0855k0.f258b.m185a(downloadVideoInfo);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsViewModel$downLoad$1$3
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
                MovieDetailsViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                MovieDetailsViewModel.this.getDownloading().setValue("");
            }
        }, false, false, null, false, 480);
    }

    @NotNull
    public final MutableLiveData<Boolean> getAlreadyTag() {
        return (MutableLiveData) this.alreadyTag.getValue();
    }

    @NotNull
    public final MutableLiveData<Boolean> getCollect() {
        return (MutableLiveData) this.collect.getValue();
    }

    @NotNull
    public final MutableLiveData<Integer> getCountdown() {
        return (MutableLiveData) this.countdown.getValue();
    }

    @NotNull
    public final MutableLiveData<VideoDetailBean> getDetailInfo() {
        return (MutableLiveData) this.detailInfo.getValue();
    }

    @NotNull
    public final MutableLiveData<String> getDownloading() {
        return (MutableLiveData) this.downloading.getValue();
    }

    @NotNull
    public final MutableLiveData<Long> getDuration() {
        return (MutableLiveData) this.duration.getValue();
    }

    public final boolean getHasAddHistory() {
        return this.hasAddHistory;
    }

    @NotNull
    public final MutableLiveData<Boolean> getHeaderPlay() {
        return (MutableLiveData) this.headerPlay.getValue();
    }

    @NotNull
    public final MutableLiveData<String> getLinkCur() {
        return (MutableLiveData) this.linkCur.getValue();
    }

    @NotNull
    public final MutableLiveData<String> getLinkId() {
        return (MutableLiveData) this.linkId.getValue();
    }

    @NotNull
    public final MutableLiveData<String> getLinkIdMulti() {
        return (MutableLiveData) this.linkIdMulti.getValue();
    }

    @NotNull
    public final MutableLiveData<String> getLinkName() {
        return (MutableLiveData) this.linkName.getValue();
    }

    @NotNull
    public final MutableLiveData<String> getMFavoriteNum() {
        return (MutableLiveData) this.mFavoriteNum.getValue();
    }

    @NotNull
    public final MutableLiveData<Boolean> getMHasFavorite() {
        return (MutableLiveData) this.mHasFavorite.getValue();
    }

    @NotNull
    public final MutableLiveData<Boolean> getMHasFolllow() {
        return (MutableLiveData) this.mHasFolllow.getValue();
    }

    @NotNull
    public final MutableLiveData<Boolean> getMHasHate() {
        return (MutableLiveData) this.mHasHate.getValue();
    }

    @NotNull
    public final MutableLiveData<Boolean> getMHasZan() {
        return (MutableLiveData) this.mHasZan.getValue();
    }

    @NotNull
    public final MutableLiveData<String> getMLoveNum() {
        return (MutableLiveData) this.mLoveNum.getValue();
    }

    @NotNull
    public final MutableLiveData<String> getMZanNum() {
        return (MutableLiveData) this.mZanNum.getValue();
    }

    @NotNull
    public final MutableLiveData<Boolean> getShowError() {
        return (MutableLiveData) this.showError.getValue();
    }

    @NotNull
    public final MutableLiveData<Boolean> getShowPlayError() {
        return (MutableLiveData) this.showPlayError.getValue();
    }

    @NotNull
    public final Timer getTimeCount() {
        return this.timeCount;
    }

    public final void loadMovie(@Nullable String id, @NotNull String link_id) {
        Intrinsics.checkNotNullParameter(link_id, "link_id");
        if (id == null || id.length() == 0) {
            return;
        }
        if (link_id.length() > 0) {
            getLinkId().setValue(link_id);
        }
        this.hasAddHistory = false;
        getLoading().setValue(new C2848a(true, null, false, false, 14));
        getShowError().setValue(Boolean.FALSE);
        C0917a c0917a = C0917a.f372a;
        HashMap m595Q = C1499a.m595Q("id", id);
        if (!(link_id.length() == 0)) {
            m595Q.put("link_id", link_id);
        }
        Unit unit = Unit.INSTANCE;
        this.job = C0917a.m221e(c0917a, "movie/detail", VideoDetailBean.class, m595Q, new Function1<VideoDetailBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsViewModel$loadMovie$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(VideoDetailBean videoDetailBean) {
                invoke2(videoDetailBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable VideoDetailBean videoDetailBean) {
                if (videoDetailBean == null) {
                    return;
                }
                MovieDetailsViewModel movieDetailsViewModel = MovieDetailsViewModel.this;
                MutableLiveData<Boolean> showError = movieDetailsViewModel.getShowError();
                Boolean bool = Boolean.FALSE;
                showError.setValue(bool);
                movieDetailsViewModel.getDetailInfo().setValue(videoDetailBean);
                movieDetailsViewModel.getMHasFavorite().setValue(Boolean.valueOf(Intrinsics.areEqual(videoDetailBean.has_favorite, "y")));
                movieDetailsViewModel.getMHasZan().setValue(Boolean.valueOf(Intrinsics.areEqual(videoDetailBean.has_love, "y")));
                movieDetailsViewModel.getMZanNum().setValue(videoDetailBean.favorite);
                movieDetailsViewModel.getLoading().setValue(new C2848a(false, null, false, false, 14));
                movieDetailsViewModel.getHeaderPlay().setValue(Boolean.TRUE);
                movieDetailsViewModel.computerCountDown(videoDetailBean.upgrade_vip_countdown);
                movieDetailsViewModel.getAlreadyTag().setValue(bool);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsViewModel$loadMovie$3
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
                MovieDetailsViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                MovieDetailsViewModel.this.getShowError().setValue(Boolean.TRUE);
            }
        }, false, false, null, false, 480);
    }

    @Override // com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel
    public void onCreate() {
    }

    public final void setHasAddHistory(boolean z) {
        this.hasAddHistory = z;
    }

    public final void setLink(@NotNull String linkUrl) {
        Intrinsics.checkNotNullParameter(linkUrl, "linkUrl");
        getLinkCur().setValue(linkUrl);
    }

    public final void setLinkName(@NotNull String linkName) {
        Intrinsics.checkNotNullParameter(linkName, "linkName");
        getLinkName().setValue(linkName);
    }

    public final void setTimeCount(@NotNull Timer timer) {
        Intrinsics.checkNotNullParameter(timer, "<set-?>");
        this.timeCount = timer;
    }

    public final void updateCountdown(int count) {
        getCountdown().setValue(Integer.valueOf(count));
    }

    public final void updateFollow(boolean hasFollow) {
        VideoDetailBean value = getDetailInfo().getValue();
        if (value == null) {
            return;
        }
        if (hasFollow) {
            value.is_follow = "y";
        } else {
            value.is_follow = "n";
        }
    }

    public final void updateLine() {
        String str;
        getHeaderPlay().setValue(Boolean.FALSE);
        MutableLiveData<Long> duration = getDuration();
        VideoDetailBean value = getDetailInfo().getValue();
        String str2 = "0";
        if (value != null && (str = value.played_duration) != null) {
            str2 = str;
        }
        duration.setValue(Long.valueOf(Long.parseLong(str2) * 1000));
        VideoDetailBean value2 = getDetailInfo().getValue();
        if (value2 == null) {
            return;
        }
        Intrinsics.checkNotNullParameter("default_line", "key");
        Intrinsics.checkNotNullParameter("", "default");
        ApplicationC2828a applicationC2828a = C2827a.f7670a;
        if (applicationC2828a == null) {
            Intrinsics.throwUninitializedPropertyAccessException("context");
            throw null;
        }
        int i2 = 0;
        SharedPreferences sharedPreferences = applicationC2828a.getSharedPreferences("default_storage", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "SupportLibraryInstance.context.getSharedPreferences(DEFAULT_STORAGE_NAME,Context.MODE_PRIVATE)");
        String string = sharedPreferences.getString("default_line", "");
        Intrinsics.checkNotNull(string);
        if (Intrinsics.areEqual(value2.play_error_type, "none")) {
            if (Intrinsics.areEqual(string, "")) {
                getLinkCur().setValue(value2.play_links.get(0).m3u8_url);
                getLinkName().setValue(value2.play_links.get(0).name);
                return;
            }
            List<VideoDetailBean.PlayLinksBean> list = value2.play_links;
            Intrinsics.checkNotNullExpressionValue(list, "it.play_links");
            for (Object obj : list) {
                int i3 = i2 + 1;
                if (i2 < 0) {
                    CollectionsKt__CollectionsKt.throwIndexOverflow();
                }
                if (Intrinsics.areEqual(((VideoDetailBean.PlayLinksBean) obj).f9995id, string)) {
                    getLinkCur().setValue(value2.play_links.get(i2).m3u8_url);
                    getLinkName().setValue(value2.play_links.get(i2).name);
                }
                i2 = i3;
            }
            return;
        }
        if (Intrinsics.areEqual(string, "")) {
            getLinkCur().setValue(value2.play_links.get(0).preview_m3u8_url);
            getLinkName().setValue(value2.play_links.get(0).name);
            return;
        }
        List<VideoDetailBean.PlayLinksBean> list2 = value2.play_links;
        Intrinsics.checkNotNullExpressionValue(list2, "it.play_links");
        for (Object obj2 : list2) {
            int i4 = i2 + 1;
            if (i2 < 0) {
                CollectionsKt__CollectionsKt.throwIndexOverflow();
            }
            if (Intrinsics.areEqual(((VideoDetailBean.PlayLinksBean) obj2).f9995id, string)) {
                getLinkCur().setValue(value2.play_links.get(i2).preview_m3u8_url);
                getLinkName().setValue(value2.play_links.get(i2).name);
            }
            i2 = i4;
        }
    }

    public final void updateLoveNum(boolean hasLove) {
        VideoDetailBean value = getDetailInfo().getValue();
        if (value == null) {
            return;
        }
        if (hasLove) {
            value.has_love = "y";
            if (!value.love.equals("") && value.loveIsNum()) {
                value.love = String.valueOf(value.getLoveNum() + 1);
            }
        } else {
            value.has_love = "n";
            if (!value.love.equals("") && value.loveIsNum()) {
                value.love = String.valueOf(value.getLoveNum() - 1);
            }
        }
        getMLoveNum().setValue(value.love);
    }

    public final void updateUnlikeUnm(boolean hasDisLike) {
        VideoDetailBean value = getDetailInfo().getValue();
        if (value == null) {
            return;
        }
        if (hasDisLike) {
            value.is_hate = "y";
        } else {
            value.is_hate = "n";
        }
        getMHasHate().setValue(Boolean.valueOf(value.getHasHate()));
    }

    public final void updateZanNum(boolean hasLike) {
        VideoDetailBean value = getDetailInfo().getValue();
        if (value == null) {
            return;
        }
        if (hasLike) {
            value.has_love = "y";
        } else {
            value.has_love = "n";
            if (value.loveIsNum()) {
                value.like = String.valueOf(value.getLikeNum() - 1);
            }
        }
        getMHasZan().setValue(Boolean.valueOf(Intrinsics.areEqual(value.has_love, "y")));
    }

    public final void userDoFollow(@NotNull String id, @NotNull final Function1<? super Boolean, Unit> success) {
        Intrinsics.checkNotNullParameter(id, "id");
        Intrinsics.checkNotNullParameter(success, "success");
        HashMap hashMap = new HashMap();
        hashMap.put("id", id);
        C0917a.m221e(C0917a.f372a, "user/doFollow", String.class, hashMap, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsViewModel$userDoFollow$1
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
                success.invoke(Boolean.TRUE);
                C4909c.m5569b().m5574g(new EventSubscription());
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDetailsViewModel$userDoFollow$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
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
                success.invoke(Boolean.FALSE);
            }
        }, false, false, null, false, 480);
    }
}

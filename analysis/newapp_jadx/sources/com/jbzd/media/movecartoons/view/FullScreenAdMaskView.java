package com.jbzd.media.movecartoons.view;

import android.app.Activity;
import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.appcompat.widget.ActivityChooserModel;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.github.mmin18.widget.RealtimeBlurView;
import com.jbzd.media.movecartoons.bean.response.comicsinfo.InnerAd;
import com.jbzd.media.movecartoons.bean.response.home.NewAd;
import com.jbzd.media.movecartoons.utils.banner.BannerAdapterImp;
import com.jbzd.media.movecartoons.view.FullScreenAdMaskView;
import com.noober.background.view.BLTextView;
import com.qnmd.adnnm.da0yzo.R;
import com.youth.banner.Banner;
import com.youth.banner.indicator.RectangleIndicator;
import com.youth.banner.listener.OnBannerListener;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.collections.CollectionsKt__IterablesKt;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.JvmOverloads;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.RangesKt___RangesKt;
import kotlin.text.StringsKt__StringNumberConversionsKt;
import kotlin.text.StringsKt__StringsKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0840d;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000w\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\t\n\u0002\u0010\u000e\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0006*\u0001$\u0018\u0000 D2\u00020\u0001:\u0002DEB\u001d\b\u0007\u0012\u0006\u0010?\u001a\u00020>\u0012\n\b\u0002\u0010A\u001a\u0004\u0018\u00010@¢\u0006\u0004\bB\u0010CJ\u001d\u0010\u0006\u001a\u00020\u00052\f\u0010\u0004\u001a\b\u0012\u0004\u0012\u00020\u00030\u0002H\u0002¢\u0006\u0004\b\u0006\u0010\u0007J\u0017\u0010\n\u001a\u00020\u00052\u0006\u0010\t\u001a\u00020\bH\u0002¢\u0006\u0004\b\n\u0010\u000bJ\u000f\u0010\f\u001a\u00020\u0005H\u0002¢\u0006\u0004\b\f\u0010\rJ\u000f\u0010\u000e\u001a\u00020\u0005H\u0002¢\u0006\u0004\b\u000e\u0010\rJ\u000f\u0010\u000f\u001a\u00020\u0005H\u0002¢\u0006\u0004\b\u000f\u0010\rJ\u0011\u0010\u0010\u001a\u0004\u0018\u00010\u0003H\u0002¢\u0006\u0004\b\u0010\u0010\u0011J!\u0010\u0015\u001a\u00020\b2\b\u0010\u0013\u001a\u0004\u0018\u00010\u00122\u0006\u0010\u0014\u001a\u00020\bH\u0002¢\u0006\u0004\b\u0015\u0010\u0016J\u0017\u0010\u0019\u001a\u00020\u00052\b\u0010\u0018\u001a\u0004\u0018\u00010\u0017¢\u0006\u0004\b\u0019\u0010\u001aJ\u0017\u0010\u001d\u001a\u00020\u00052\b\u0010\u001c\u001a\u0004\u0018\u00010\u001b¢\u0006\u0004\b\u001d\u0010\u001eJ\r\u0010\u001f\u001a\u00020\u0005¢\u0006\u0004\b\u001f\u0010\rJ\u000f\u0010 \u001a\u00020\u0005H\u0014¢\u0006\u0004\b \u0010\rR\u0016\u0010\"\u001a\u00020!8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\"\u0010#R\u0016\u0010%\u001a\u00020$8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b%\u0010&R\u0018\u0010'\u001a\u0004\u0018\u00010\u00178\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b'\u0010(R\u0016\u0010)\u001a\u00020\b8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b)\u0010*R\u0016\u0010,\u001a\u00020+8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b,\u0010-R\u0016\u0010.\u001a\u00020\b8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b.\u0010*R\u0016\u00100\u001a\u00020/8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b0\u00101R%\u00107\u001a\n\u0012\u0002\b\u0003\u0012\u0002\b\u0003028F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b3\u00104\u001a\u0004\b5\u00106R\u0016\u00108\u001a\u00020!8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b8\u0010#R\u0016\u0010:\u001a\u0002098\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b:\u0010;R\u001c\u0010<\u001a\b\u0012\u0004\u0012\u00020\u00030\u00028\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b<\u0010=¨\u0006F"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/view/FullScreenAdMaskView;", "Landroidx/constraintlayout/widget/ConstraintLayout;", "", "Lcom/jbzd/media/movecartoons/bean/response/home/NewAd;", "list", "", "bindBanner", "(Ljava/util/List;)V", "", "seconds", "startCountdown", "(I)V", "stopCountdown", "()V", "updateCountdownText", "enableDismiss", "getCurrentAdOrNull", "()Lcom/jbzd/media/movecartoons/bean/response/home/NewAd;", "", "raw", "defaultValue", "parseSeconds", "(Ljava/lang/String;I)I", "Lcom/jbzd/media/movecartoons/view/FullScreenAdMaskView$Listener;", "l", "setListener", "(Lcom/jbzd/media/movecartoons/view/FullScreenAdMaskView$Listener;)V", "Lcom/jbzd/media/movecartoons/bean/response/comicsinfo/InnerAd;", "innerAd", "show", "(Lcom/jbzd/media/movecartoons/bean/response/comicsinfo/InnerAd;)V", "dismiss", "onDetachedFromWindow", "Lcom/noober/background/view/BLTextView;", "btnMain", "Lcom/noober/background/view/BLTextView;", "com/jbzd/media/movecartoons/view/FullScreenAdMaskView$tickRunnable$1", "tickRunnable", "Lcom/jbzd/media/movecartoons/view/FullScreenAdMaskView$tickRunnable$1;", "listener", "Lcom/jbzd/media/movecartoons/view/FullScreenAdMaskView$Listener;", "leftSeconds", "I", "Lcom/github/mmin18/widget/RealtimeBlurView;", "blurView", "Lcom/github/mmin18/widget/RealtimeBlurView;", "currentIndex", "Landroid/os/Handler;", "mainHandler", "Landroid/os/Handler;", "Lcom/youth/banner/Banner;", "banner$delegate", "Lkotlin/Lazy;", "getBanner", "()Lcom/youth/banner/Banner;", "banner", "btnVip", "Landroid/widget/TextView;", "tvCountdown", "Landroid/widget/TextView;", "currentAds", "Ljava/util/List;", "Landroid/content/Context;", "context", "Landroid/util/AttributeSet;", "attrs", "<init>", "(Landroid/content/Context;Landroid/util/AttributeSet;)V", "Companion", "Listener", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class FullScreenAdMaskView extends ConstraintLayout {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: banner$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy banner;

    @NotNull
    private final RealtimeBlurView blurView;

    @NotNull
    private final BLTextView btnMain;

    @NotNull
    private final BLTextView btnVip;

    @NotNull
    private List<? extends NewAd> currentAds;
    private int currentIndex;
    private int leftSeconds;

    @Nullable
    private Listener listener;

    @NotNull
    private final Handler mainHandler;

    @NotNull
    private final FullScreenAdMaskView$tickRunnable$1 tickRunnable;

    @NotNull
    private final TextView tvCountdown;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006¨\u0006\t"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/view/FullScreenAdMaskView$Companion;", "", "Landroid/app/Activity;", ActivityChooserModel.ATTRIBUTE_ACTIVITY, "Lcom/jbzd/media/movecartoons/view/FullScreenAdMaskView;", "attachTo", "(Landroid/app/Activity;)Lcom/jbzd/media/movecartoons/view/FullScreenAdMaskView;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX WARN: Multi-variable type inference failed */
        @NotNull
        public final FullScreenAdMaskView attachTo(@NotNull Activity activity) {
            Intrinsics.checkNotNullParameter(activity, "activity");
            Window window = activity.getWindow();
            AttributeSet attributeSet = null;
            Object[] objArr = 0;
            View decorView = window == null ? null : window.getDecorView();
            Objects.requireNonNull(decorView, "null cannot be cast to non-null type android.view.ViewGroup");
            FullScreenAdMaskView fullScreenAdMaskView = new FullScreenAdMaskView(activity, attributeSet, 2, objArr == true ? 1 : 0);
            ((ViewGroup) decorView).addView(fullScreenAdMaskView, new ViewGroup.LayoutParams(-1, -1));
            return fullScreenAdMaskView;
        }
    }

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0006\bf\u0018\u00002\u00020\u0001J\u0019\u0010\u0005\u001a\u00020\u00042\b\u0010\u0003\u001a\u0004\u0018\u00010\u0002H&¢\u0006\u0004\b\u0005\u0010\u0006J\u0019\u0010\u0007\u001a\u00020\u00042\b\u0010\u0003\u001a\u0004\u0018\u00010\u0002H&¢\u0006\u0004\b\u0007\u0010\u0006J\u000f\u0010\b\u001a\u00020\u0004H&¢\u0006\u0004\b\b\u0010\t¨\u0006\n"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/view/FullScreenAdMaskView$Listener;", "", "Lcom/jbzd/media/movecartoons/bean/response/home/NewAd;", "current", "", "onVipClick", "(Lcom/jbzd/media/movecartoons/bean/response/home/NewAd;)V", "onMainButtonClick", "onDismiss", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public interface Listener {
        void onDismiss();

        void onMainButtonClick(@Nullable NewAd current);

        void onVipClick(@Nullable NewAd current);
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    @JvmOverloads
    public FullScreenAdMaskView(@NotNull Context context) {
        this(context, null, 2, 0 == true ? 1 : 0);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    public /* synthetic */ FullScreenAdMaskView(Context context, AttributeSet attributeSet, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this(context, (i2 & 2) != 0 ? null : attributeSet);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: _init_$lambda-0, reason: not valid java name */
    public static final void m6032_init_$lambda0(View view) {
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: _init_$lambda-1, reason: not valid java name */
    public static final void m6033_init_$lambda1(FullScreenAdMaskView this$0, View view) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Listener listener = this$0.listener;
        if (listener == null) {
            return;
        }
        listener.onVipClick(this$0.getCurrentAdOrNull());
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: _init_$lambda-2, reason: not valid java name */
    public static final void m6034_init_$lambda2(FullScreenAdMaskView this$0, View view) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Listener listener = this$0.listener;
        if (listener == null) {
            return;
        }
        listener.onMainButtonClick(this$0.getCurrentAdOrNull());
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: _init_$lambda-3, reason: not valid java name */
    public static final void m6035_init_$lambda3(View view) {
    }

    private final void bindBanner(final List<? extends NewAd> list) {
        final Banner<?, ?> banner = getBanner();
        Banner intercept = banner.setIntercept(list.size() != 1);
        Context context = banner.getContext();
        Intrinsics.checkNotNullExpressionValue(context, "context");
        ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(list, 10));
        Iterator<T> it = list.iterator();
        while (it.hasNext()) {
            arrayList.add(((NewAd) it.next()).content);
        }
        intercept.setAdapter(new BannerAdapterImp(context, arrayList, 0.0f, 10.0d, ImageView.ScaleType.FIT_XY, 4));
        banner.setOnBannerListener(new OnBannerListener() { // from class: b.a.a.a.u.i
            @Override // com.youth.banner.listener.OnBannerListener
            public final void OnBannerClick(Object obj, int i2) {
                FullScreenAdMaskView.m6036bindBanner$lambda6$lambda5(Banner.this, list, obj, i2);
            }
        });
        banner.setIndicator(new RectangleIndicator(banner.getContext()));
        banner.start();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindBanner$lambda-6$lambda-5, reason: not valid java name */
    public static final void m6036bindBanner$lambda6$lambda5(Banner this_run, List list, Object obj, int i2) {
        Intrinsics.checkNotNullParameter(this_run, "$this_run");
        Intrinsics.checkNotNullParameter(list, "$list");
        C0840d.a aVar = C0840d.f235a;
        Context context = this_run.getContext();
        Intrinsics.checkNotNullExpressionValue(context, "context");
        aVar.m177c(context, (NewAd) list.get(i2));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void enableDismiss() {
        this.tvCountdown.setText("继续看下一话  >");
        this.tvCountdown.setEnabled(true);
        this.tvCountdown.setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.u.g
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                FullScreenAdMaskView.m6037enableDismiss$lambda7(FullScreenAdMaskView.this, view);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: enableDismiss$lambda-7, reason: not valid java name */
    public static final void m6037enableDismiss$lambda7(FullScreenAdMaskView this$0, View view) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.dismiss();
    }

    private final NewAd getCurrentAdOrNull() {
        if (this.currentAds.isEmpty()) {
            return null;
        }
        return this.currentAds.get(RangesKt___RangesKt.coerceIn(this.currentIndex, 0, this.currentAds.size() - 1));
    }

    private final int parseSeconds(String raw, int defaultValue) {
        Integer intOrNull;
        String obj = raw == null ? null : StringsKt__StringsKt.trim((CharSequence) raw).toString();
        if (obj != null && (intOrNull = StringsKt__StringNumberConversionsKt.toIntOrNull(obj)) != null) {
            defaultValue = intOrNull.intValue();
        }
        return Math.max(1, defaultValue);
    }

    private final void startCountdown(int seconds) {
        stopCountdown();
        this.leftSeconds = seconds;
        updateCountdownText();
        if (this.leftSeconds > 0) {
            this.mainHandler.postDelayed(this.tickRunnable, 1000L);
        } else {
            enableDismiss();
        }
    }

    private final void stopCountdown() {
        this.mainHandler.removeCallbacks(this.tickRunnable);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void updateCountdownText() {
        if (this.leftSeconds <= 0) {
            this.tvCountdown.setText("看下一话  >");
            this.tvCountdown.setEnabled(true);
            return;
        }
        this.tvCountdown.setText(this.leftSeconds + " 秒后可看下一话  >");
        this.tvCountdown.setEnabled(false);
    }

    public void _$_clearFindViewByIdCache() {
    }

    public final void dismiss() {
        stopCountdown();
        try {
            getBanner().stop();
        } catch (Throwable unused) {
        }
        setVisibility(8);
        Listener listener = this.listener;
        if (listener == null) {
            return;
        }
        listener.onDismiss();
    }

    @NotNull
    public final Banner<?, ?> getBanner() {
        return (Banner) this.banner.getValue();
    }

    @Override // android.view.ViewGroup, android.view.View
    public void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        stopCountdown();
        try {
            getBanner().stop();
        } catch (Throwable unused) {
        }
    }

    public final void setListener(@Nullable Listener l2) {
        this.listener = l2;
    }

    public final void show(@Nullable InnerAd innerAd) {
        List<NewAd> list = innerAd == null ? null : innerAd.ads;
        if (list == null) {
            list = CollectionsKt__CollectionsKt.emptyList();
        }
        List<? extends NewAd> filterNotNull = CollectionsKt___CollectionsKt.filterNotNull(list);
        if (filterNotNull.isEmpty()) {
            return;
        }
        this.currentAds = filterNotNull;
        this.leftSeconds = parseSeconds(innerAd != null ? innerAd.time : null, 5);
        bindBanner(this.currentAds);
        this.currentIndex = 0;
        getBanner().setCurrentItem(this.currentIndex, false);
        startCountdown(this.leftSeconds);
        setVisibility(0);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Type inference failed for: r5v5, types: [com.jbzd.media.movecartoons.view.FullScreenAdMaskView$tickRunnable$1] */
    @JvmOverloads
    public FullScreenAdMaskView(@NotNull Context context, @Nullable AttributeSet attributeSet) {
        super(context, attributeSet);
        Intrinsics.checkNotNullParameter(context, "context");
        this.mainHandler = new Handler(Looper.getMainLooper());
        this.currentAds = CollectionsKt__CollectionsKt.emptyList();
        this.banner = LazyKt__LazyJVMKt.lazy(new Function0<Banner<?, ?>>() { // from class: com.jbzd.media.movecartoons.view.FullScreenAdMaskView$banner$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final Banner<?, ?> invoke() {
                Banner<?, ?> banner = (Banner) FullScreenAdMaskView.this.findViewById(R.id.banner_splash);
                Intrinsics.checkNotNull(banner);
                return banner;
            }
        });
        this.tickRunnable = new Runnable() { // from class: com.jbzd.media.movecartoons.view.FullScreenAdMaskView$tickRunnable$1
            @Override // java.lang.Runnable
            public void run() {
                int i2;
                int i3;
                Handler handler;
                FullScreenAdMaskView fullScreenAdMaskView = FullScreenAdMaskView.this;
                i2 = fullScreenAdMaskView.leftSeconds;
                fullScreenAdMaskView.leftSeconds = i2 - 1;
                FullScreenAdMaskView.this.updateCountdownText();
                i3 = FullScreenAdMaskView.this.leftSeconds;
                if (i3 <= 0) {
                    FullScreenAdMaskView.this.enableDismiss();
                } else {
                    handler = FullScreenAdMaskView.this.mainHandler;
                    handler.postDelayed(this, 1000L);
                }
            }
        };
        LayoutInflater.from(context).inflate(R.layout.view_fullscreen_ad_mask, (ViewGroup) this, true);
        View findViewById = findViewById(R.id.blurView);
        Intrinsics.checkNotNullExpressionValue(findViewById, "findViewById(R.id.blurView)");
        RealtimeBlurView realtimeBlurView = (RealtimeBlurView) findViewById;
        this.blurView = realtimeBlurView;
        View findViewById2 = findViewById(R.id.btnVip);
        Intrinsics.checkNotNullExpressionValue(findViewById2, "findViewById(R.id.btnVip)");
        BLTextView bLTextView = (BLTextView) findViewById2;
        this.btnVip = bLTextView;
        View findViewById3 = findViewById(R.id.btnMain);
        Intrinsics.checkNotNullExpressionValue(findViewById3, "findViewById(R.id.btnMain)");
        BLTextView bLTextView2 = (BLTextView) findViewById3;
        this.btnMain = bLTextView2;
        View findViewById4 = findViewById(R.id.tvCountdown);
        Intrinsics.checkNotNullExpressionValue(findViewById4, "findViewById(R.id.tvCountdown)");
        TextView textView = (TextView) findViewById4;
        this.tvCountdown = textView;
        setVisibility(8);
        realtimeBlurView.setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.u.f
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                FullScreenAdMaskView.m6032_init_$lambda0(view);
            }
        });
        bLTextView.setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.u.h
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                FullScreenAdMaskView.m6033_init_$lambda1(FullScreenAdMaskView.this, view);
            }
        });
        bLTextView2.setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.u.j
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                FullScreenAdMaskView.m6034_init_$lambda2(FullScreenAdMaskView.this, view);
            }
        });
        textView.setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.u.e
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                FullScreenAdMaskView.m6035_init_$lambda3(view);
            }
        });
    }
}

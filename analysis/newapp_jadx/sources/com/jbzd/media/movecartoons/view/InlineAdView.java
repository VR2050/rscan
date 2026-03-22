package com.jbzd.media.movecartoons.view;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.core.app.NotificationCompat;
import com.blankj.utilcode.util.ToastUtils;
import com.jbzd.media.movecartoons.bean.response.comicsinfo.InnerAd;
import com.jbzd.media.movecartoons.bean.response.home.NewAd;
import com.jbzd.media.movecartoons.utils.banner.BannerAdapterImp;
import com.jbzd.media.movecartoons.view.InlineAdView;
import com.noober.background.view.BLTextView;
import com.qnmd.adnnm.da0yzo.R;
import com.youth.banner.Banner;
import com.youth.banner.indicator.RectangleIndicator;
import com.youth.banner.listener.OnBannerListener;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.collections.CollectionsKt__IterablesKt;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.JvmOverloads;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.RangesKt___RangesKt;
import kotlin.text.StringsKt__StringNumberConversionsKt;
import kotlin.text.StringsKt__StringsJVMKt;
import kotlin.text.StringsKt__StringsKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0840d;
import p005b.p139f.p140a.p142b.C1550t;
import p005b.p139f.p140a.p142b.RunnableC1543m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u008f\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0006\n\u0002\u0010\u000b\n\u0002\b\u0006\n\u0002\u0010\u000e\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\u0007\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005*\u0001=\u0018\u00002\u00020\u0001:\u0001SB\u001d\b\u0007\u0012\u0006\u0010N\u001a\u00020M\u0012\n\b\u0002\u0010P\u001a\u0004\u0018\u00010O¢\u0006\u0004\bQ\u0010RJ\u001d\u0010\u0006\u001a\u00020\u00052\f\u0010\u0004\u001a\b\u0012\u0004\u0012\u00020\u00030\u0002H\u0002¢\u0006\u0004\b\u0006\u0010\u0007J\u0017\u0010\n\u001a\u00020\u00052\u0006\u0010\t\u001a\u00020\bH\u0002¢\u0006\u0004\b\n\u0010\u000bJ\u000f\u0010\f\u001a\u00020\u0005H\u0002¢\u0006\u0004\b\f\u0010\rJ\u000f\u0010\u000e\u001a\u00020\u0005H\u0002¢\u0006\u0004\b\u000e\u0010\rJ\u0017\u0010\u0011\u001a\u00020\u00052\u0006\u0010\u0010\u001a\u00020\u000fH\u0002¢\u0006\u0004\b\u0011\u0010\u0012J\u000f\u0010\u0013\u001a\u00020\u0005H\u0002¢\u0006\u0004\b\u0013\u0010\rJ\u0011\u0010\u0014\u001a\u0004\u0018\u00010\u0003H\u0002¢\u0006\u0004\b\u0014\u0010\u0015J!\u0010\u0019\u001a\u00020\b2\b\u0010\u0017\u001a\u0004\u0018\u00010\u00162\u0006\u0010\u0018\u001a\u00020\bH\u0002¢\u0006\u0004\b\u0019\u0010\u001aJ\u0017\u0010\u001d\u001a\u00020\u00052\b\u0010\u001c\u001a\u0004\u0018\u00010\u001b¢\u0006\u0004\b\u001d\u0010\u001eJ\u0017\u0010!\u001a\u00020\u00052\b\u0010 \u001a\u0004\u0018\u00010\u001f¢\u0006\u0004\b!\u0010\"J\r\u0010#\u001a\u00020\u0005¢\u0006\u0004\b#\u0010\rJ\u0017\u0010&\u001a\u00020\u000f2\u0006\u0010%\u001a\u00020$H\u0016¢\u0006\u0004\b&\u0010'J\u0017\u0010)\u001a\u00020\u000f2\u0006\u0010(\u001a\u00020$H\u0016¢\u0006\u0004\b)\u0010'J\u000f\u0010*\u001a\u00020\u0005H\u0014¢\u0006\u0004\b*\u0010\rR\u0016\u0010,\u001a\u00020+8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b,\u0010-R\u0016\u0010.\u001a\u00020\b8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b.\u0010/R\u0016\u00100\u001a\u00020\b8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b0\u0010/R\u0016\u00102\u001a\u0002018\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b2\u00103R\u0016\u00104\u001a\u00020\u000f8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b4\u00105R\u001e\u00107\u001a\n\u0012\u0002\b\u0003\u0012\u0002\b\u0003068\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b7\u00108R\u0016\u0010:\u001a\u0002098\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b:\u0010;R\u0016\u0010<\u001a\u00020\u000f8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b<\u00105R\u0016\u0010>\u001a\u00020=8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b>\u0010?R\u0016\u0010A\u001a\u00020@8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\bA\u0010BR\u0016\u0010C\u001a\u0002018\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\bC\u00103R\u001c\u0010D\u001a\b\u0012\u0004\u0012\u00020\u00030\u00028\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\bD\u0010ER\u0016\u0010G\u001a\u00020F8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\bG\u0010HR\u0018\u0010I\u001a\u0004\u0018\u00010\u001b8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\bI\u0010JR\u0016\u0010K\u001a\u00020\b8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\bK\u0010/R\u0016\u0010L\u001a\u0002098\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\bL\u0010;¨\u0006T"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/view/InlineAdView;", "Landroidx/constraintlayout/widget/ConstraintLayout;", "", "Lcom/jbzd/media/movecartoons/bean/response/home/NewAd;", "list", "", "bindBanner", "(Ljava/util/List;)V", "", "seconds", "startCountdown", "(I)V", "stopCountdown", "()V", "updateCountdownText", "", "enable", "setOutsideBlock", "(Z)V", "dismissInternal", "getCurrentAdOrNull", "()Lcom/jbzd/media/movecartoons/bean/response/home/NewAd;", "", "raw", "defaultValue", "parseSeconds", "(Ljava/lang/String;I)I", "Lcom/jbzd/media/movecartoons/view/InlineAdView$Listener;", "l", "setListener", "(Lcom/jbzd/media/movecartoons/view/InlineAdView$Listener;)V", "Lcom/jbzd/media/movecartoons/bean/response/comicsinfo/InnerAd;", "innerAd", "show", "(Lcom/jbzd/media/movecartoons/bean/response/comicsinfo/InnerAd;)V", "dismiss", "Landroid/view/MotionEvent;", "ev", "onInterceptTouchEvent", "(Landroid/view/MotionEvent;)Z", NotificationCompat.CATEGORY_EVENT, "onTouchEvent", "onDetachedFromWindow", "Landroid/os/Handler;", "mainHandler", "Landroid/os/Handler;", "touchSlop", "I", "currentIndex", "", "downX", "F", "interceptingVertical", "Z", "Lcom/youth/banner/Banner;", "banner", "Lcom/youth/banner/Banner;", "Landroid/view/View;", "touchBlocker", "Landroid/view/View;", "blockTouch", "com/jbzd/media/movecartoons/view/InlineAdView$tickRunnable$1", "tickRunnable", "Lcom/jbzd/media/movecartoons/view/InlineAdView$tickRunnable$1;", "Lcom/noober/background/view/BLTextView;", "btnVip", "Lcom/noober/background/view/BLTextView;", "downY", "currentAds", "Ljava/util/List;", "Landroid/widget/TextView;", "tvCountdown", "Landroid/widget/TextView;", "listener", "Lcom/jbzd/media/movecartoons/view/InlineAdView$Listener;", "leftSeconds", "card", "Landroid/content/Context;", "context", "Landroid/util/AttributeSet;", "attrs", "<init>", "(Landroid/content/Context;Landroid/util/AttributeSet;)V", "Listener", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class InlineAdView extends ConstraintLayout {

    @NotNull
    private final Banner<?, ?> banner;
    private boolean blockTouch;

    @NotNull
    private final BLTextView btnVip;

    @NotNull
    private final View card;

    @NotNull
    private List<? extends NewAd> currentAds;
    private int currentIndex;
    private float downX;
    private float downY;
    private boolean interceptingVertical;
    private int leftSeconds;

    @Nullable
    private Listener listener;

    @NotNull
    private final Handler mainHandler;

    @NotNull
    private final InlineAdView$tickRunnable$1 tickRunnable;

    @NotNull
    private final View touchBlocker;
    private final int touchSlop;

    @NotNull
    private final TextView tvCountdown;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0003\bf\u0018\u00002\u00020\u0001J\u0019\u0010\u0005\u001a\u00020\u00042\b\u0010\u0003\u001a\u0004\u0018\u00010\u0002H&¢\u0006\u0004\b\u0005\u0010\u0006¨\u0006\u0007"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/view/InlineAdView$Listener;", "", "Lcom/jbzd/media/movecartoons/bean/response/home/NewAd;", "current", "", "onVipClick", "(Lcom/jbzd/media/movecartoons/bean/response/home/NewAd;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public interface Listener {
        void onVipClick(@Nullable NewAd current);
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    @JvmOverloads
    public InlineAdView(@NotNull Context context) {
        this(context, null, 2, 0 == true ? 1 : 0);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    public /* synthetic */ InlineAdView(Context context, AttributeSet attributeSet, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this(context, (i2 & 2) != 0 ? null : attributeSet);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: _init_$lambda-0, reason: not valid java name */
    public static final void m6038_init_$lambda0(InlineAdView this$0, View view) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Listener listener = this$0.listener;
        if (listener == null) {
            return;
        }
        listener.onVipClick(this$0.getCurrentAdOrNull());
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: _init_$lambda-1, reason: not valid java name */
    public static final void m6039_init_$lambda1(View view) {
    }

    private final void bindBanner(final List<? extends NewAd> list) {
        final Banner<?, ?> banner = this.banner;
        Banner intercept = banner.setIntercept(list.size() != 1);
        Context context = banner.getContext();
        Intrinsics.checkNotNullExpressionValue(context, "context");
        ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(list, 10));
        Iterator<T> it = list.iterator();
        while (it.hasNext()) {
            arrayList.add(((NewAd) it.next()).content);
        }
        intercept.setAdapter(new BannerAdapterImp(context, arrayList, 0.0f, 10.0d, ImageView.ScaleType.FIT_XY, 4));
        banner.setOnBannerListener(new OnBannerListener() { // from class: b.a.a.a.u.o
            @Override // com.youth.banner.listener.OnBannerListener
            public final void OnBannerClick(Object obj, int i2) {
                InlineAdView.m6040bindBanner$lambda6$lambda5(InlineAdView.this, banner, list, obj, i2);
            }
        });
        banner.setIndicator(new RectangleIndicator(banner.getContext()));
        banner.start();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindBanner$lambda-6$lambda-5, reason: not valid java name */
    public static final void m6040bindBanner$lambda6$lambda5(InlineAdView this$0, Banner this_run, List list, Object obj, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(this_run, "$this_run");
        Intrinsics.checkNotNullParameter(list, "$list");
        this$0.currentIndex = i2;
        C0840d.a aVar = C0840d.f235a;
        Context context = this_run.getContext();
        Intrinsics.checkNotNullExpressionValue(context, "context");
        aVar.m177c(context, (NewAd) list.get(i2));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void dismissInternal() {
        stopCountdown();
        try {
            this.banner.stop();
        } catch (Throwable unused) {
        }
        this.blockTouch = false;
        this.interceptingVertical = false;
        setOutsideBlock(false);
        setVisibility(8);
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

    private final void setOutsideBlock(boolean enable) {
        if (enable) {
            this.touchBlocker.setClickable(true);
            this.touchBlocker.setFocusable(true);
            this.touchBlocker.setOnTouchListener(new View.OnTouchListener() { // from class: b.a.a.a.u.k
                @Override // android.view.View.OnTouchListener
                public final boolean onTouch(View view, MotionEvent motionEvent) {
                    boolean m6041setOutsideBlock$lambda7;
                    m6041setOutsideBlock$lambda7 = InlineAdView.m6041setOutsideBlock$lambda7(view, motionEvent);
                    return m6041setOutsideBlock$lambda7;
                }
            });
        } else {
            this.touchBlocker.setOnTouchListener(null);
            this.touchBlocker.setClickable(false);
            this.touchBlocker.setFocusable(false);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: setOutsideBlock$lambda-7, reason: not valid java name */
    public static final boolean m6041setOutsideBlock$lambda7(View view, MotionEvent motionEvent) {
        return true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: show$lambda-3, reason: not valid java name */
    public static final void m6042show$lambda3(InlineAdView this$0) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.card.bringToFront();
        this$0.btnVip.bringToFront();
        this$0.tvCountdown.bringToFront();
    }

    private final void startCountdown(int seconds) {
        stopCountdown();
        this.leftSeconds = seconds;
        updateCountdownText();
        if (this.leftSeconds > 0) {
            this.mainHandler.postDelayed(this.tickRunnable, 1000L);
        } else {
            dismissInternal();
        }
    }

    private final void stopCountdown() {
        this.mainHandler.removeCallbacks(this.tickRunnable);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void updateCountdownText() {
        if (this.leftSeconds > 0) {
            this.tvCountdown.setText(this.leftSeconds + " 秒后可继续阅读");
            this.tvCountdown.setEnabled(false);
        }
    }

    public void _$_clearFindViewByIdCache() {
    }

    public final void dismiss() {
        dismissInternal();
    }

    @Override // android.view.ViewGroup, android.view.View
    public void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        dismissInternal();
    }

    @Override // android.view.ViewGroup
    public boolean onInterceptTouchEvent(@NotNull MotionEvent ev) {
        Intrinsics.checkNotNullParameter(ev, "ev");
        if (!this.blockTouch) {
            return super.onInterceptTouchEvent(ev);
        }
        int actionMasked = ev.getActionMasked();
        if (actionMasked == 0) {
            this.downX = ev.getX();
            this.downY = ev.getY();
            this.interceptingVertical = false;
            return false;
        }
        if (actionMasked != 1) {
            if (actionMasked == 2) {
                float abs = Math.abs(ev.getX() - this.downX);
                float abs2 = Math.abs(ev.getY() - this.downY);
                if (this.interceptingVertical || abs2 <= this.touchSlop || abs2 <= abs) {
                    return false;
                }
                this.interceptingVertical = true;
                return true;
            }
            if (actionMasked != 3) {
                return super.onInterceptTouchEvent(ev);
            }
        }
        this.interceptingVertical = false;
        return false;
    }

    @Override // android.view.View
    public boolean onTouchEvent(@NotNull MotionEvent event) {
        Intrinsics.checkNotNullParameter(event, "event");
        return !this.blockTouch ? super.onTouchEvent(event) : this.interceptingVertical;
    }

    public final void setListener(@Nullable Listener l2) {
        this.listener = l2;
    }

    public final void show(@Nullable InnerAd innerAd) {
        String stringPlus = Intrinsics.stringPlus(innerAd == null ? null : innerAd.time, "秒后可解锁内容");
        ToastUtils toastUtils = ToastUtils.f8825a;
        ToastUtils toastUtils2 = ToastUtils.f8825a;
        if (stringPlus == null) {
            stringPlus = "toast null";
        } else if (stringPlus.length() == 0) {
            stringPlus = "toast nothing";
        }
        C1550t.m731h(new RunnableC1543m(toastUtils2, null, stringPlus, 0));
        stopCountdown();
        try {
            this.banner.stop();
        } catch (Throwable unused) {
        }
        List<NewAd> list = innerAd == null ? null : innerAd.ads;
        if (list == null) {
            list = CollectionsKt__CollectionsKt.emptyList();
        }
        List filterNotNull = CollectionsKt___CollectionsKt.filterNotNull(list);
        ArrayList arrayList = new ArrayList();
        for (Object obj : filterNotNull) {
            String str = ((NewAd) obj).content;
            Intrinsics.checkNotNullExpressionValue(str, "it.content");
            if (true ^ StringsKt__StringsJVMKt.isBlank(str)) {
                arrayList.add(obj);
            }
        }
        if (arrayList.isEmpty()) {
            dismissInternal();
            return;
        }
        this.currentAds = arrayList;
        this.blockTouch = true;
        this.interceptingVertical = false;
        setClickable(true);
        setFocusable(true);
        setFocusableInTouchMode(true);
        setOutsideBlock(true);
        this.leftSeconds = parseSeconds(innerAd != null ? innerAd.time : null, 5);
        updateCountdownText();
        bindBanner(this.currentAds);
        this.currentIndex = 0;
        try {
            this.banner.setCurrentItem(0, false);
        } catch (Throwable unused2) {
        }
        post(new Runnable() { // from class: b.a.a.a.u.n
            @Override // java.lang.Runnable
            public final void run() {
                InlineAdView.m6042show$lambda3(InlineAdView.this);
            }
        });
        setVisibility(0);
        startCountdown(this.leftSeconds);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Type inference failed for: r4v5, types: [com.jbzd.media.movecartoons.view.InlineAdView$tickRunnable$1] */
    @JvmOverloads
    public InlineAdView(@NotNull Context context, @Nullable AttributeSet attributeSet) {
        super(context, attributeSet);
        Intrinsics.checkNotNullParameter(context, "context");
        this.mainHandler = new Handler(Looper.getMainLooper());
        this.touchSlop = ViewConfiguration.get(context).getScaledTouchSlop();
        this.currentAds = CollectionsKt__CollectionsKt.emptyList();
        this.tickRunnable = new Runnable() { // from class: com.jbzd.media.movecartoons.view.InlineAdView$tickRunnable$1
            @Override // java.lang.Runnable
            public void run() {
                int i2;
                int i3;
                Handler handler;
                InlineAdView inlineAdView = InlineAdView.this;
                i2 = inlineAdView.leftSeconds;
                inlineAdView.leftSeconds = i2 - 1;
                InlineAdView.this.updateCountdownText();
                i3 = InlineAdView.this.leftSeconds;
                if (i3 <= 0) {
                    InlineAdView.this.dismissInternal();
                } else {
                    handler = InlineAdView.this.mainHandler;
                    handler.postDelayed(this, 1000L);
                }
            }
        };
        LayoutInflater.from(context).inflate(R.layout.view_inline_ad, (ViewGroup) this, true);
        View findViewById = findViewById(R.id.btnVip);
        Intrinsics.checkNotNullExpressionValue(findViewById, "findViewById(R.id.btnVip)");
        BLTextView bLTextView = (BLTextView) findViewById;
        this.btnVip = bLTextView;
        View findViewById2 = findViewById(R.id.tvCountdown);
        Intrinsics.checkNotNullExpressionValue(findViewById2, "findViewById(R.id.tvCountdown)");
        TextView textView = (TextView) findViewById2;
        this.tvCountdown = textView;
        View findViewById3 = findViewById(R.id.touchBlocker);
        Intrinsics.checkNotNullExpressionValue(findViewById3, "findViewById(R.id.touchBlocker)");
        this.touchBlocker = findViewById3;
        View findViewById4 = findViewById(R.id.card);
        Intrinsics.checkNotNullExpressionValue(findViewById4, "findViewById(R.id.card)");
        this.card = findViewById4;
        View findViewById5 = findViewById(R.id.banner);
        Intrinsics.checkNotNullExpressionValue(findViewById5, "findViewById(R.id.banner)");
        this.banner = (Banner) findViewById5;
        setVisibility(8);
        setOutsideBlock(false);
        bLTextView.setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.u.m
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                InlineAdView.m6038_init_$lambda0(InlineAdView.this, view);
            }
        });
        textView.setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.u.l
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                InlineAdView.m6039_init_$lambda1(view);
            }
        });
    }
}

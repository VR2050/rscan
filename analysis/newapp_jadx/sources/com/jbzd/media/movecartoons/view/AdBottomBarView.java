package com.jbzd.media.movecartoons.view;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import com.jbzd.media.movecartoons.bean.response.comicsinfo.InnerAd;
import com.jbzd.media.movecartoons.bean.response.home.NewAd;
import com.jbzd.media.movecartoons.view.AdBottomBarView;
import com.noober.background.view.BLConstraintLayout;
import com.qnmd.adnnm.da0yzo.R;
import java.util.ArrayList;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.jvm.JvmOverloads;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.random.Random;
import kotlin.text.StringsKt__StringNumberConversionsKt;
import kotlin.text.StringsKt__StringsJVMKt;
import kotlin.text.StringsKt__StringsKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0840d;
import p005b.p143g.p144a.ComponentCallbacks2C1553c;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000r\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010\t\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010 \n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\u0018\u00002\u00020\u0001:\u0001<B\u001d\b\u0007\u0012\u0006\u00107\u001a\u000206\u0012\n\b\u0002\u00109\u001a\u0004\u0018\u000108¢\u0006\u0004\b:\u0010;J\u000f\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0003\u0010\u0004J\u000f\u0010\u0006\u001a\u00020\u0005H\u0002¢\u0006\u0004\b\u0006\u0010\u0007J\u000f\u0010\b\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\b\u0010\u0004J\u000f\u0010\t\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\t\u0010\u0004J!\u0010\u000f\u001a\u00020\u000e2\b\u0010\u000b\u001a\u0004\u0018\u00010\n2\u0006\u0010\r\u001a\u00020\fH\u0002¢\u0006\u0004\b\u000f\u0010\u0010J\u0017\u0010\u0013\u001a\u00020\u00022\b\u0010\u0012\u001a\u0004\u0018\u00010\u0011¢\u0006\u0004\b\u0013\u0010\u0014J\u0017\u0010\u0017\u001a\u00020\u00022\b\u0010\u0016\u001a\u0004\u0018\u00010\u0015¢\u0006\u0004\b\u0017\u0010\u0018J\r\u0010\u0019\u001a\u00020\u0002¢\u0006\u0004\b\u0019\u0010\u0004J\r\u0010\u001a\u001a\u00020\u0002¢\u0006\u0004\b\u001a\u0010\u0004J\u000f\u0010\u001b\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\u001b\u0010\u0004R\u0016\u0010\u001d\u001a\u00020\u001c8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\u001d\u0010\u001eR\u0016\u0010\u001f\u001a\u00020\u001c8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\u001f\u0010\u001eR\u0016\u0010!\u001a\u00020 8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b!\u0010\"R\u0018\u0010#\u001a\u0004\u0018\u00010\u00118\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b#\u0010$R\u0016\u0010&\u001a\u00020%8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b&\u0010'R\u0018\u0010(\u001a\u0004\u0018\u00010\u00058\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b(\u0010)R\u0018\u0010*\u001a\u0004\u0018\u00010\n8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b*\u0010+R\u001c\u0010-\u001a\b\u0012\u0004\u0012\u00020\u00050,8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b-\u0010.R\u0016\u0010/\u001a\u00020\u000e8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b/\u00100R\u0016\u00102\u001a\u0002018\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b2\u00103R\u0016\u00104\u001a\u00020%8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b4\u0010'R\u0016\u00105\u001a\u00020\u001c8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b5\u0010\u001e¨\u0006="}, m5311d2 = {"Lcom/jbzd/media/movecartoons/view/AdBottomBarView;", "Lcom/noober/background/view/BLConstraintLayout;", "", "showRandom", "()V", "Lcom/jbzd/media/movecartoons/bean/response/home/NewAd;", "pickRandomAvoidSame", "()Lcom/jbzd/media/movecartoons/bean/response/home/NewAd;", "hideAndScheduleReopen", "cancelReopen", "", "rawSeconds", "", "defaultSeconds", "", "parseDelayMs", "(Ljava/lang/String;I)J", "Lcom/jbzd/media/movecartoons/view/AdBottomBarView$Listener;", "l", "setListener", "(Lcom/jbzd/media/movecartoons/view/AdBottomBarView$Listener;)V", "Lcom/jbzd/media/movecartoons/bean/response/comicsinfo/InnerAd;", "innerAd", "setInnerAd", "(Lcom/jbzd/media/movecartoons/bean/response/comicsinfo/InnerAd;)V", "show", "hide", "onDetachedFromWindow", "Landroid/widget/TextView;", "btnVip", "Landroid/widget/TextView;", "tvTitle", "Ljava/lang/Runnable;", "reopenRunnable", "Ljava/lang/Runnable;", "listener", "Lcom/jbzd/media/movecartoons/view/AdBottomBarView$Listener;", "Landroid/widget/ImageView;", "ivClose", "Landroid/widget/ImageView;", "current", "Lcom/jbzd/media/movecartoons/bean/response/home/NewAd;", "lastShownId", "Ljava/lang/String;", "", "data", "Ljava/util/List;", "reopenDelayMs", "J", "Landroid/os/Handler;", "mainHandler", "Landroid/os/Handler;", "ivCover", "tvSub", "Landroid/content/Context;", "context", "Landroid/util/AttributeSet;", "attrs", "<init>", "(Landroid/content/Context;Landroid/util/AttributeSet;)V", "Listener", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class AdBottomBarView extends BLConstraintLayout {

    @NotNull
    private final TextView btnVip;

    @Nullable
    private NewAd current;

    @NotNull
    private List<? extends NewAd> data;

    @NotNull
    private final ImageView ivClose;

    @NotNull
    private final ImageView ivCover;

    @Nullable
    private String lastShownId;

    @Nullable
    private Listener listener;

    @NotNull
    private final Handler mainHandler;
    private long reopenDelayMs;

    @NotNull
    private final Runnable reopenRunnable;

    @NotNull
    private final TextView tvSub;

    @NotNull
    private final TextView tvTitle;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\bf\u0018\u00002\u00020\u0001J\u0019\u0010\u0005\u001a\u00020\u00042\b\u0010\u0003\u001a\u0004\u0018\u00010\u0002H&¢\u0006\u0004\b\u0005\u0010\u0006J\u0019\u0010\b\u001a\u00020\u00042\b\u0010\u0007\u001a\u0004\u0018\u00010\u0002H&¢\u0006\u0004\b\b\u0010\u0006¨\u0006\t"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/view/AdBottomBarView$Listener;", "", "Lcom/jbzd/media/movecartoons/bean/response/home/NewAd;", "currentAd", "", "onVipClick", "(Lcom/jbzd/media/movecartoons/bean/response/home/NewAd;)V", "lastAd", "onAdClosed", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public interface Listener {
        void onAdClosed(@Nullable NewAd lastAd);

        void onVipClick(@Nullable NewAd currentAd);
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    @JvmOverloads
    public AdBottomBarView(@NotNull Context context) {
        this(context, null, 2, 0 == true ? 1 : 0);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    public /* synthetic */ AdBottomBarView(Context context, AttributeSet attributeSet, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this(context, (i2 & 2) != 0 ? null : attributeSet);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: _init_$lambda-2, reason: not valid java name */
    public static final void m6028_init_$lambda2(AdBottomBarView this$0, Context context, View view) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(context, "$context");
        NewAd newAd = this$0.current;
        if (newAd == null) {
            return;
        }
        C0840d.f235a.m177c(context, newAd);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: _init_$lambda-3, reason: not valid java name */
    public static final void m6029_init_$lambda3(AdBottomBarView this$0, View view) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Listener listener = this$0.listener;
        if (listener == null) {
            return;
        }
        listener.onVipClick(this$0.current);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: _init_$lambda-4, reason: not valid java name */
    public static final void m6030_init_$lambda4(AdBottomBarView this$0, View view) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.hideAndScheduleReopen();
    }

    private final void cancelReopen() {
        this.mainHandler.removeCallbacks(this.reopenRunnable);
    }

    private final void hideAndScheduleReopen() {
        Listener listener = this.listener;
        if (listener != null) {
            listener.onAdClosed(this.current);
        }
        setVisibility(8);
        this.mainHandler.postDelayed(this.reopenRunnable, this.reopenDelayMs);
    }

    private final long parseDelayMs(String rawSeconds, int defaultSeconds) {
        String obj;
        Long l2 = null;
        if (rawSeconds != null && (obj = StringsKt__StringsKt.trim((CharSequence) rawSeconds).toString()) != null) {
            l2 = StringsKt__StringNumberConversionsKt.toLongOrNull(obj);
        }
        long longValue = l2 == null ? defaultSeconds : l2.longValue();
        if (longValue <= 0) {
            longValue = defaultSeconds;
        }
        return longValue * 1000;
    }

    private final NewAd pickRandomAvoidSame() {
        if (this.data.size() == 1) {
            return this.data.get(0);
        }
        List<? extends NewAd> list = this.data;
        List arrayList = new ArrayList();
        for (Object obj : list) {
            if (!Intrinsics.areEqual(((NewAd) obj).f10022id, this.lastShownId)) {
                arrayList.add(obj);
            }
        }
        if (!(!arrayList.isEmpty())) {
            arrayList = this.data;
        }
        return (NewAd) arrayList.get(Random.INSTANCE.nextInt(arrayList.size()));
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: reopenRunnable$lambda-0, reason: not valid java name */
    public static final void m6031reopenRunnable$lambda0(AdBottomBarView this$0) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        if (this$0.isAttachedToWindow() && (!this$0.data.isEmpty())) {
            this$0.showRandom();
        }
    }

    private final void showRandom() {
        cancelReopen();
        NewAd pickRandomAvoidSame = pickRandomAvoidSame();
        this.current = pickRandomAvoidSame;
        TextView textView = this.tvTitle;
        String str = pickRandomAvoidSame.name;
        if (str == null) {
            str = "广告名称";
        }
        textView.setText(str);
        TextView textView2 = this.tvSub;
        String str2 = pickRandomAvoidSame.name;
        if (str2 == null) {
            str2 = "";
        }
        textView2.setText(str2);
        String imageUrl = pickRandomAvoidSame.content;
        Intrinsics.checkNotNullExpressionValue(imageUrl, "imageUrl");
        if (!StringsKt__StringsJVMKt.isBlank(imageUrl)) {
            ComponentCallbacks2C1553c.m739i(this).mo775h(imageUrl).mo1083d().m757R(this.ivCover);
        } else {
            this.ivCover.setImageDrawable(null);
        }
        setVisibility(0);
        this.lastShownId = pickRandomAvoidSame.f10022id;
    }

    public void _$_clearFindViewByIdCache() {
    }

    public final void hide() {
        cancelReopen();
        setVisibility(8);
    }

    @Override // android.view.ViewGroup, android.view.View
    public void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        cancelReopen();
    }

    public final void setInnerAd(@Nullable InnerAd innerAd) {
        List<NewAd> list = innerAd == null ? null : innerAd.ads;
        if (list == null) {
            list = CollectionsKt__CollectionsKt.emptyList();
        }
        this.data = list;
        this.reopenDelayMs = parseDelayMs(innerAd == null ? null : innerAd.time, 20);
        if (this.data.isEmpty()) {
            cancelReopen();
            setVisibility(8);
            this.current = null;
        }
    }

    public final void setListener(@Nullable Listener l2) {
        this.listener = l2;
    }

    public final void show() {
        if (this.data.isEmpty()) {
            return;
        }
        showRandom();
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    @JvmOverloads
    public AdBottomBarView(@NotNull final Context context, @Nullable AttributeSet attributeSet) {
        super(context, attributeSet);
        Intrinsics.checkNotNullParameter(context, "context");
        this.mainHandler = new Handler(Looper.getMainLooper());
        this.reopenDelayMs = 20000L;
        this.data = CollectionsKt__CollectionsKt.emptyList();
        this.reopenRunnable = new Runnable() { // from class: b.a.a.a.u.d
            @Override // java.lang.Runnable
            public final void run() {
                AdBottomBarView.m6031reopenRunnable$lambda0(AdBottomBarView.this);
            }
        };
        LayoutInflater.from(context).inflate(R.layout.view_ad_bottom_bar, (ViewGroup) this, true);
        View findViewById = findViewById(R.id.ivCover);
        Intrinsics.checkNotNullExpressionValue(findViewById, "findViewById(R.id.ivCover)");
        ImageView imageView = (ImageView) findViewById;
        this.ivCover = imageView;
        View findViewById2 = findViewById(R.id.ivClose);
        Intrinsics.checkNotNullExpressionValue(findViewById2, "findViewById(R.id.ivClose)");
        ImageView imageView2 = (ImageView) findViewById2;
        this.ivClose = imageView2;
        View findViewById3 = findViewById(R.id.tvTitle);
        Intrinsics.checkNotNullExpressionValue(findViewById3, "findViewById(R.id.tvTitle)");
        this.tvTitle = (TextView) findViewById3;
        View findViewById4 = findViewById(R.id.tvSub);
        Intrinsics.checkNotNullExpressionValue(findViewById4, "findViewById(R.id.tvSub)");
        this.tvSub = (TextView) findViewById4;
        View findViewById5 = findViewById(R.id.btnVip);
        Intrinsics.checkNotNullExpressionValue(findViewById5, "findViewById(R.id.btnVip)");
        TextView textView = (TextView) findViewById5;
        this.btnVip = textView;
        setVisibility(8);
        imageView.setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.u.c
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                AdBottomBarView.m6028_init_$lambda2(AdBottomBarView.this, context, view);
            }
        });
        textView.setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.u.a
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                AdBottomBarView.m6029_init_$lambda3(AdBottomBarView.this, view);
            }
        });
        imageView2.setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.u.b
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                AdBottomBarView.m6030_init_$lambda4(AdBottomBarView.this, view);
            }
        });
    }
}

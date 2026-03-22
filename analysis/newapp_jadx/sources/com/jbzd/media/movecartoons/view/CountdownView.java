package com.jbzd.media.movecartoons.view;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;
import com.jbzd.media.movecartoons.R$styleable;
import com.jbzd.media.movecartoons.p396ui.index.home.child.VideoListActivity;
import com.qnmd.adnnm.da0yzo.R;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.JvmOverloads;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.C3079m0;
import p379c.p380a.C3109w0;
import p379c.p380a.InterfaceC3053d1;
import p379c.p380a.p381a.C2964m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000f\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010\u0011\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010\u000b\n\u0002\b\n\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010\t\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\u0018\u00002\u00020\u0001B)\b\u0007\u0012\b\u00109\u001a\u0004\u0018\u000108\u0012\n\b\u0002\u0010;\u001a\u0004\u0018\u00010:\u0012\b\b\u0002\u0010<\u001a\u00020\u0005¢\u0006\u0004\b=\u0010>J\u000f\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0003\u0010\u0004J\u0017\u0010\u0007\u001a\u00020\u00022\u0006\u0010\u0006\u001a\u00020\u0005H\u0003¢\u0006\u0004\b\u0007\u0010\bJB\u0010\u0011\u001a\u00020\u00022\u0006\u0010\n\u001a\u00020\t2\b\b\u0002\u0010\u000b\u001a\u00020\t2!\u0010\u0010\u001a\u001d\u0012\u0013\u0012\u00110\t¢\u0006\f\b\r\u0012\b\b\u000e\u0012\u0004\b\b(\u000f\u0012\u0004\u0012\u00020\u00020\f¢\u0006\u0004\b\u0011\u0010\u0012J\r\u0010\u0013\u001a\u00020\u0002¢\u0006\u0004\b\u0013\u0010\u0004J%\u0010\u0017\u001a\u00020\u00022\u0016\u0010\u0016\u001a\f\u0012\b\b\u0001\u0012\u0004\u0018\u00010\u00150\u0014\"\u0004\u0018\u00010\u0015¢\u0006\u0004\b\u0017\u0010\u0018R\u0016\u0010\u000b\u001a\u00020\t8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u000b\u0010\u0019R\u0018\u0010\u001a\u001a\u0004\u0018\u00010\u00158\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u001a\u0010\u001bR=\u0010\u001e\u001a\u001d\u0012\u0013\u0012\u00110\u001c¢\u0006\f\b\r\u0012\b\b\u000e\u0012\u0004\b\b(\u001d\u0012\u0004\u0012\u00020\u00020\f8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u001e\u0010\u001f\u001a\u0004\b \u0010!\"\u0004\b\"\u0010#R=\u0010$\u001a\u001d\u0012\u0013\u0012\u00110\t¢\u0006\f\b\r\u0012\b\b\u000e\u0012\u0004\b\b(\u000f\u0012\u0004\u0012\u00020\u00020\f8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b$\u0010\u001f\u001a\u0004\b%\u0010!\"\u0004\b&\u0010#R%\u0010-\u001a\n (*\u0004\u0018\u00010'0'8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b)\u0010*\u001a\u0004\b+\u0010,R\u0016\u0010\u0006\u001a\u00020.8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0006\u0010/R\u0016\u00100\u001a\u00020\u00058\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b0\u00101R\u001d\u00106\u001a\u0002028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b3\u0010*\u001a\u0004\b4\u00105R\u0016\u00107\u001a\u00020\u00058\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b7\u00101¨\u0006?"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/view/CountdownView;", "Landroid/widget/LinearLayout;", "", "start", "()V", "", "gap", "setView", "(I)V", "", "endDateStr", VideoListActivity.KEY_TITLE, "Lkotlin/Function1;", "Lkotlin/ParameterName;", "name", "time", "timeBlockSumbit", "setEndDate", "(Ljava/lang/String;Ljava/lang/String;Lkotlin/jvm/functions/Function1;)V", "stop", "", "Lc/a/d1;", "jobs", "cancelJob", "([Lkotlinx/coroutines/Job;)V", "Ljava/lang/String;", "jobCountDown", "Lc/a/d1;", "", "timeOut", "expiredBlock", "Lkotlin/jvm/functions/Function1;", "getExpiredBlock", "()Lkotlin/jvm/functions/Function1;", "setExpiredBlock", "(Lkotlin/jvm/functions/Function1;)V", "timedBlock", "getTimedBlock", "setTimedBlock", "Landroid/view/View;", "kotlin.jvm.PlatformType", "mRoot$delegate", "Lkotlin/Lazy;", "getMRoot", "()Landroid/view/View;", "mRoot", "", "J", "textColor", "I", "Landroid/widget/TextView;", "tv$delegate", "getTv", "()Landroid/widget/TextView;", "tv", "textSize", "Landroid/content/Context;", "context", "Landroid/util/AttributeSet;", "attrs", "defStyleAttr", "<init>", "(Landroid/content/Context;Landroid/util/AttributeSet;I)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class CountdownView extends LinearLayout {

    @NotNull
    private Function1<? super Boolean, Unit> expiredBlock;
    private long gap;

    @Nullable
    private InterfaceC3053d1 jobCountDown;

    /* renamed from: mRoot$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mRoot;
    private int textColor;
    private int textSize;

    @NotNull
    private Function1<? super String, Unit> timedBlock;

    @NotNull
    private String title;

    /* renamed from: tv$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv;

    @JvmOverloads
    public CountdownView(@Nullable Context context) {
        this(context, null, 0, 6, null);
    }

    @JvmOverloads
    public CountdownView(@Nullable Context context, @Nullable AttributeSet attributeSet) {
        this(context, attributeSet, 0, 4, null);
    }

    public /* synthetic */ CountdownView(Context context, AttributeSet attributeSet, int i2, int i3, DefaultConstructorMarker defaultConstructorMarker) {
        this(context, (i3 & 2) != 0 ? null : attributeSet, (i3 & 4) != 0 ? 0 : i2);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final View getMRoot() {
        return (View) this.mRoot.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final TextView getTv() {
        return (TextView) this.tv.getValue();
    }

    public static /* synthetic */ void setEndDate$default(CountdownView countdownView, String str, String str2, Function1 function1, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            str2 = "倒计时:";
        }
        countdownView.setEndDate(str, str2, function1);
    }

    /* JADX INFO: Access modifiers changed from: private */
    @SuppressLint({"SetTextI18n"})
    public final void setView(int gap) {
        getTv().setText(this.title + ' ' + (gap / 3600) + ':' + ((gap % 3600) / 60) + ':' + ((gap % 1440) % 60));
    }

    private final void start() {
        getTv().setTextColor(this.textColor);
        getTv().getPaint().setTextSize(this.textSize);
        setView((int) this.gap);
        cancelJob(this.jobCountDown);
        C3109w0 c3109w0 = C3109w0.f8471c;
        C3079m0 c3079m0 = C3079m0.f8432c;
        this.jobCountDown = C2354n.m2435U0(c3109w0, C2964m.f8127b, 0, new CountdownView$start$1(this, null), 2, null);
    }

    public void _$_clearFindViewByIdCache() {
    }

    public final void cancelJob(@NotNull InterfaceC3053d1... jobs) {
        Intrinsics.checkNotNullParameter(jobs, "jobs");
        for (InterfaceC3053d1 interfaceC3053d1 : jobs) {
            if (interfaceC3053d1 != null && interfaceC3053d1.mo3507b()) {
                C2354n.m2512s(interfaceC3053d1, null, 1, null);
            }
        }
    }

    @NotNull
    public final Function1<Boolean, Unit> getExpiredBlock() {
        return this.expiredBlock;
    }

    @NotNull
    public final Function1<String, Unit> getTimedBlock() {
        return this.timedBlock;
    }

    public final void setEndDate(@NotNull String endDateStr, @NotNull String title, @NotNull Function1<? super String, Unit> timeBlockSumbit) {
        Intrinsics.checkNotNullParameter(endDateStr, "endDateStr");
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(timeBlockSumbit, "timeBlockSumbit");
        this.timedBlock = timeBlockSumbit;
        try {
            this.title = title;
            long parseLong = Long.parseLong(endDateStr);
            this.gap = parseLong;
            if (parseLong > 0) {
                start();
            } else {
                getTv().setVisibility(8);
                this.expiredBlock.invoke(Boolean.FALSE);
            }
        } catch (Exception e2) {
            e2.printStackTrace();
        }
    }

    public final void setExpiredBlock(@NotNull Function1<? super Boolean, Unit> function1) {
        Intrinsics.checkNotNullParameter(function1, "<set-?>");
        this.expiredBlock = function1;
    }

    public final void setTimedBlock(@NotNull Function1<? super String, Unit> function1) {
        Intrinsics.checkNotNullParameter(function1, "<set-?>");
        this.timedBlock = function1;
    }

    public final void stop() {
        InterfaceC3053d1 interfaceC3053d1 = this.jobCountDown;
        if (interfaceC3053d1 != null) {
            C2354n.m2512s(interfaceC3053d1, null, 1, null);
        }
        getTv().setText("");
    }

    @JvmOverloads
    public CountdownView(@Nullable final Context context, @Nullable AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        this.textColor = -1;
        Intrinsics.checkNotNull(context);
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.CountdownView);
        this.textColor = obtainStyledAttributes.getColor(1, -1);
        this.textSize = obtainStyledAttributes.getDimensionPixelSize(0, (int) ((context.getResources().getDisplayMetrics().scaledDensity * 16.0f) + 0.5f));
        obtainStyledAttributes.recycle();
        this.mRoot = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.view.CountdownView$mRoot$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final View invoke() {
                return View.inflate(context, R.layout.coubtdown_view, this);
            }
        });
        this.expiredBlock = new Function1<Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.view.CountdownView$expiredBlock$1
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Boolean bool) {
                invoke(bool.booleanValue());
                return Unit.INSTANCE;
            }

            public final void invoke(boolean z) {
            }
        };
        this.timedBlock = new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.view.CountdownView$timedBlock$1
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str) {
                invoke2(str);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull String it) {
                Intrinsics.checkNotNullParameter(it, "it");
            }
        };
        this.tv = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.view.CountdownView$tv$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View mRoot;
                mRoot = CountdownView.this.getMRoot();
                View findViewById = mRoot.findViewById(R.id.tv_time);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.TextView");
                return (TextView) findViewById;
            }
        });
        this.title = "";
    }
}

package com.drake.statelayout;

import android.content.Context;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.os.Handler;
import android.os.Looper;
import android.util.ArrayMap;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.annotation.LayoutRes;
import androidx.core.app.NotificationCompat;
import com.drake.statelayout.C1871d;
import com.drake.statelayout.StateChangedHandler;
import com.drake.statelayout.StateConfig;
import com.drake.statelayout.StateLayout;
import com.drake.statelayout.Status;
import com.drake.statelayout.StatusInfo;
import com.drake.statelayout.ThrottleClickListener;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.JvmOverloads;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5310d1 = {"\u0000z\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\t\n\u0002\b\u000e\n\u0002\u0010\u000b\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\u0010\u0015\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u000b\u0018\u00002\u00020\u0001B%\b\u0007\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\n\b\u0002\u0010\u0004\u001a\u0004\u0018\u00010\u0005\u0012\b\b\u0002\u0010\u0006\u001a\u00020\u0007¢\u0006\u0002\u0010\bJ\u001a\u0010G\u001a\u00020#2\u0006\u0010@\u001a\u00020?2\b\u0010'\u001a\u0004\u0018\u00010$H\u0002J6\u0010!\u001a\u00020\u00002.\u0010H\u001a*\u0012\u0004\u0012\u00020#\u0012\u0015\u0012\u0013\u0018\u00010$¢\u0006\f\b%\u0012\b\b&\u0012\u0004\b\b('\u0012\u0004\u0012\u00020(0\"¢\u0006\u0002\b)J6\u0010,\u001a\u00020\u00002.\u0010H\u001a*\u0012\u0004\u0012\u00020#\u0012\u0015\u0012\u0013\u0018\u00010$¢\u0006\f\b%\u0012\b\b&\u0012\u0004\b\b('\u0012\u0004\u0012\u00020(0\"¢\u0006\u0002\b)J6\u0010.\u001a\u00020\u00002.\u0010H\u001a*\u0012\u0004\u0012\u00020#\u0012\u0015\u0012\u0013\u0018\u00010$¢\u0006\f\b%\u0012\b\b&\u0012\u0004\b\b('\u0012\u0004\u0012\u00020(0\"¢\u0006\u0002\b)J\b\u0010I\u001a\u00020(H\u0014J6\u00100\u001a\u00020\u00002.\u0010H\u001a*\u0012\u0004\u0012\u00020#\u0012\u0015\u0012\u0013\u0018\u00010$¢\u0006\f\b%\u0012\b\b&\u0012\u0004\b\b('\u0012\u0004\u0012\u00020(0\"¢\u0006\u0002\b)J6\u00102\u001a\u00020\u00002.\u0010H\u001a*\u0012\u0004\u0012\u00020\u0000\u0012\u0015\u0012\u0013\u0018\u00010$¢\u0006\f\b%\u0012\b\b&\u0012\u0004\b\b('\u0012\u0004\u0012\u00020(0\"¢\u0006\u0002\b)J\u0006\u0010J\u001a\u00020(J\u0012\u0010K\u001a\u00020(2\n\b\u0002\u0010'\u001a\u0004\u0018\u00010$J\u0010\u0010L\u001a\u00020(2\u0006\u0010@\u001a\u00020?H\u0002J\u0016\u0010M\u001a\u00020(2\f\u0010H\u001a\b\u0012\u0004\u0012\u00020(0NH\u0002J\u000e\u0010O\u001a\u00020(2\u0006\u0010P\u001a\u00020#J\u0014\u0010Q\u001a\u00020\u00002\f\b\u0001\u0010R\u001a\u000204\"\u00020\u0007J\u0012\u0010S\u001a\u00020(2\n\b\u0002\u0010'\u001a\u0004\u0018\u00010$J\u0012\u0010T\u001a\u00020(2\n\b\u0002\u0010'\u001a\u0004\u0018\u00010$J\u0012\u0010U\u001a\u00020(2\n\b\u0002\u0010'\u001a\u0004\u0018\u00010$J&\u0010V\u001a\u00020(2\n\b\u0002\u0010'\u001a\u0004\u0018\u00010$2\b\b\u0002\u0010W\u001a\u00020\u00192\b\b\u0002\u0010J\u001a\u00020\u0019J\u001c\u0010X\u001a\u00020(2\u0006\u0010@\u001a\u00020?2\n\b\u0002\u0010'\u001a\u0004\u0018\u00010$H\u0002J\u0006\u0010F\u001a\u00020\u0019R\u001a\u0010\t\u001a\u00020\nX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u000b\u0010\f\"\u0004\b\r\u0010\u000eR&\u0010\u0010\u001a\u00020\u00072\u0006\u0010\u000f\u001a\u00020\u00078F@FX\u0087\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0011\u0010\u0012\"\u0004\b\u0013\u0010\u0014R&\u0010\u0015\u001a\u00020\u00072\u0006\u0010\u000f\u001a\u00020\u00078F@FX\u0087\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0016\u0010\u0012\"\u0004\b\u0017\u0010\u0014R\u001a\u0010\u0018\u001a\u00020\u0019X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u001a\u0010\u001b\"\u0004\b\u001c\u0010\u001dR&\u0010\u001e\u001a\u00020\u00072\u0006\u0010\u000f\u001a\u00020\u00078F@FX\u0087\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u001f\u0010\u0012\"\u0004\b \u0010\u0014R@\u0010!\u001a,\u0012\u0004\u0012\u00020#\u0012\u0015\u0012\u0013\u0018\u00010$¢\u0006\f\b%\u0012\b\b&\u0012\u0004\b\b('\u0012\u0004\u0012\u00020(\u0018\u00010\"¢\u0006\u0002\b)8BX\u0082\u000e¢\u0006\b\n\u0000\u001a\u0004\b*\u0010+R@\u0010,\u001a,\u0012\u0004\u0012\u00020#\u0012\u0015\u0012\u0013\u0018\u00010$¢\u0006\f\b%\u0012\b\b&\u0012\u0004\b\b('\u0012\u0004\u0012\u00020(\u0018\u00010\"¢\u0006\u0002\b)8BX\u0082\u000e¢\u0006\b\n\u0000\u001a\u0004\b-\u0010+R@\u0010.\u001a,\u0012\u0004\u0012\u00020#\u0012\u0015\u0012\u0013\u0018\u00010$¢\u0006\f\b%\u0012\b\b&\u0012\u0004\b\b('\u0012\u0004\u0012\u00020(\u0018\u00010\"¢\u0006\u0002\b)8BX\u0082\u000e¢\u0006\b\n\u0000\u001a\u0004\b/\u0010+R@\u00100\u001a,\u0012\u0004\u0012\u00020#\u0012\u0015\u0012\u0013\u0018\u00010$¢\u0006\f\b%\u0012\b\b&\u0012\u0004\b\b('\u0012\u0004\u0012\u00020(\u0018\u00010\"¢\u0006\u0002\b)8BX\u0082\u000e¢\u0006\b\n\u0000\u001a\u0004\b1\u0010+R8\u00102\u001a,\u0012\u0004\u0012\u00020\u0000\u0012\u0015\u0012\u0013\u0018\u00010$¢\u0006\f\b%\u0012\b\b&\u0012\u0004\b\b('\u0012\u0004\u0012\u00020(\u0018\u00010\"¢\u0006\u0002\b)X\u0082\u000e¢\u0006\u0002\n\u0000R\u0018\u00103\u001a\u0004\u0018\u0001048BX\u0082\u000e¢\u0006\b\n\u0000\u001a\u0004\b5\u00106R\u000e\u00107\u001a\u00020\u0019X\u0082\u000e¢\u0006\u0002\n\u0000R\u001a\u00108\u001a\u000209X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b:\u0010;\"\u0004\b<\u0010=R\u001e\u0010@\u001a\u00020?2\u0006\u0010>\u001a\u00020?@BX\u0086\u000e¢\u0006\b\n\u0000\u001a\u0004\bA\u0010BR\u001a\u0010C\u001a\u000e\u0012\u0004\u0012\u00020?\u0012\u0004\u0012\u00020E0DX\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010F\u001a\u00020\u0019X\u0082\u000e¢\u0006\u0002\n\u0000¨\u0006Y"}, m5311d2 = {"Lcom/drake/statelayout/StateLayout;", "Landroid/widget/FrameLayout;", "context", "Landroid/content/Context;", "attrs", "Landroid/util/AttributeSet;", "defStyleAttr", "", "(Landroid/content/Context;Landroid/util/AttributeSet;I)V", "clickThrottle", "", "getClickThrottle", "()J", "setClickThrottle", "(J)V", "value", "emptyLayout", "getEmptyLayout", "()I", "setEmptyLayout", "(I)V", "errorLayout", "getErrorLayout", "setErrorLayout", "loaded", "", "getLoaded", "()Z", "setLoaded", "(Z)V", "loadingLayout", "getLoadingLayout", "setLoadingLayout", "onContent", "Lkotlin/Function2;", "Landroid/view/View;", "", "Lkotlin/ParameterName;", "name", "tag", "", "Lkotlin/ExtensionFunctionType;", "getOnContent", "()Lkotlin/jvm/functions/Function2;", "onEmpty", "getOnEmpty", "onError", "getOnError", "onLoading", "getOnLoading", "onRefresh", "retryIds", "", "getRetryIds", "()[I", "stateChanged", "stateChangedHandler", "Lcom/drake/statelayout/StateChangedHandler;", "getStateChangedHandler", "()Lcom/drake/statelayout/StateChangedHandler;", "setStateChangedHandler", "(Lcom/drake/statelayout/StateChangedHandler;)V", "<set-?>", "Lcom/drake/statelayout/Status;", NotificationCompat.CATEGORY_STATUS, "getStatus", "()Lcom/drake/statelayout/Status;", "statusMap", "Landroid/util/ArrayMap;", "Lcom/drake/statelayout/StatusInfo;", "trigger", "getStatusView", "block", "onFinishInflate", "refresh", "refreshing", "removeStatus", "runMain", "Lkotlin/Function0;", "setContent", "view", "setRetryIds", "ids", "showContent", "showEmpty", "showError", "showLoading", NotificationCompat.GROUP_KEY_SILENT, "showStatus", "statelayout_release"}, m5312k = 1, m5313mv = {1, 6, 0}, m5315xi = 48)
/* loaded from: classes.dex */
public final class StateLayout extends FrameLayout {

    /* renamed from: c */
    public static final /* synthetic */ int f9018c = 0;

    /* renamed from: e */
    @NotNull
    public final ArrayMap<Status, StatusInfo> f9019e;

    /* renamed from: f */
    @Nullable
    public Function2<? super StateLayout, Object, Unit> f9020f;

    /* renamed from: g */
    @NotNull
    public Status f9021g;

    /* renamed from: h */
    public boolean f9022h;

    /* renamed from: i */
    public long f9023i;

    /* renamed from: j */
    @NotNull
    public StateChangedHandler f9024j;

    /* renamed from: k */
    @LayoutRes
    public int f9025k;

    /* renamed from: l */
    @LayoutRes
    public int f9026l;

    /* renamed from: m */
    @LayoutRes
    public int f9027m;

    @Metadata(m5310d1 = {"\u0000\b\n\u0000\n\u0002\u0010\u0002\n\u0000\u0010\u0000\u001a\u00020\u0001H\n¢\u0006\u0002\b\u0002"}, m5311d2 = {"<anonymous>", "", "invoke"}, m5312k = 3, m5313mv = {1, 6, 0}, m5315xi = 48)
    /* renamed from: com.drake.statelayout.StateLayout$a */
    public static final class C3248a extends Lambda implements Function0<Unit> {

        /* renamed from: e */
        public final /* synthetic */ Status f9029e;

        /* renamed from: f */
        public final /* synthetic */ Object f9030f;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C3248a(Status status, Object obj) {
            super(0);
            this.f9029e = status;
            this.f9030f = obj;
        }

        @Override // kotlin.jvm.functions.Function0
        public Unit invoke() {
            int i2;
            int[] retryIds;
            Function2 onContent;
            try {
                View m3993f = StateLayout.m3993f(StateLayout.this, this.f9029e, this.f9030f);
                ArrayMap<Status, StatusInfo> arrayMap = StateLayout.this.f9019e;
                Status status = this.f9029e;
                LinkedHashMap linkedHashMap = new LinkedHashMap();
                Iterator<Map.Entry<Status, StatusInfo>> it = arrayMap.entrySet().iterator();
                while (true) {
                    if (!it.hasNext()) {
                        break;
                    }
                    Map.Entry<Status, StatusInfo> next = it.next();
                    if ((next.getKey() != status ? 1 : 0) != 0) {
                        linkedHashMap.put(next.getKey(), next.getValue());
                    }
                }
                StateLayout stateLayout = StateLayout.this;
                for (Map.Entry entry : linkedHashMap.entrySet()) {
                    StatusInfo statusInfo = (StatusInfo) entry.getValue();
                    if (entry.getKey() == stateLayout.getF9021g()) {
                        StateChangedHandler f9024j = stateLayout.getF9024j();
                        View view = statusInfo.f2887a;
                        Object key = entry.getKey();
                        Intrinsics.checkNotNullExpressionValue(key, "it.key");
                        f9024j.mo1209a(stateLayout, view, (Status) key, statusInfo.f2888b);
                    }
                }
                StateLayout.this.getF9024j().mo1210b(StateLayout.this, m3993f, this.f9029e, this.f9030f);
                Status status2 = this.f9029e;
                if ((status2 == Status.EMPTY || status2 == Status.ERROR) && (retryIds = StateLayout.this.getRetryIds()) != null) {
                    StateLayout stateLayout2 = StateLayout.this;
                    int length = retryIds.length;
                    while (i2 < length) {
                        View findViewById = m3993f.findViewById(retryIds[i2]);
                        if (findViewById != null) {
                            Intrinsics.checkNotNullExpressionValue(findViewById, "findViewById<View>(it)");
                            long f9023i = stateLayout2.getF9023i();
                            C1871d block = new C1871d(stateLayout2);
                            TimeUnit unit = TimeUnit.MILLISECONDS;
                            Intrinsics.checkNotNullParameter(findViewById, "<this>");
                            Intrinsics.checkNotNullParameter(unit, "unit");
                            Intrinsics.checkNotNullParameter(block, "block");
                            findViewById.setOnClickListener(new ThrottleClickListener(f9023i, unit, block));
                        }
                        i2++;
                    }
                }
                int ordinal = this.f9029e.ordinal();
                if (ordinal == 0) {
                    Function2 onLoading = StateLayout.this.getOnLoading();
                    if (onLoading != null) {
                        onLoading.invoke(m3993f, this.f9030f);
                    }
                } else if (ordinal == 1) {
                    Function2 onEmpty = StateLayout.this.getOnEmpty();
                    if (onEmpty != null) {
                        onEmpty.invoke(m3993f, this.f9030f);
                    }
                } else if (ordinal == 2) {
                    Function2 onError = StateLayout.this.getOnError();
                    if (onError != null) {
                        onError.invoke(m3993f, this.f9030f);
                    }
                } else if (ordinal == 3 && (onContent = StateLayout.this.getOnContent()) != null) {
                    onContent.invoke(m3993f, this.f9030f);
                }
                StateLayout.this.f9021g = this.f9029e;
            } catch (Exception unused) {
                StateLayout.this.getClass().getSimpleName();
            }
            return Unit.INSTANCE;
        }
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    @JvmOverloads
    public StateLayout(@NotNull Context context) {
        this(context, null, 0, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    @JvmOverloads
    public StateLayout(@NotNull Context context, @Nullable AttributeSet attributeSet) {
        this(context, attributeSet, 0, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    public /* synthetic */ StateLayout(Context context, AttributeSet attributeSet, int i2, int i3) {
        this(context, (i3 & 2) != 0 ? null : attributeSet, (i3 & 4) != 0 ? 0 : i2);
    }

    /* renamed from: f */
    public static final View m3993f(StateLayout stateLayout, Status status, Object obj) {
        int loadingLayout;
        StatusInfo statusInfo = stateLayout.f9019e.get(status);
        if (statusInfo != null) {
            statusInfo.f2888b = obj;
            return statusInfo.f2887a;
        }
        int ordinal = status.ordinal();
        if (ordinal == 0) {
            loadingLayout = stateLayout.getLoadingLayout();
        } else if (ordinal == 1) {
            loadingLayout = stateLayout.getEmptyLayout();
        } else if (ordinal == 2) {
            loadingLayout = stateLayout.getErrorLayout();
        } else {
            if (ordinal != 3) {
                throw new NoWhenBranchMatchedException();
            }
            loadingLayout = -1;
        }
        if (loadingLayout != -1) {
            View view = LayoutInflater.from(stateLayout.getContext()).inflate(loadingLayout, (ViewGroup) stateLayout, false);
            ArrayMap<Status, StatusInfo> arrayMap = stateLayout.f9019e;
            Intrinsics.checkNotNullExpressionValue(view, "view");
            arrayMap.put(status, new StatusInfo(view, obj));
            return view;
        }
        int ordinal2 = status.ordinal();
        if (ordinal2 == 0) {
            throw new Resources.NotFoundException("No StateLayout loadingLayout is set");
        }
        if (ordinal2 == 1) {
            throw new Resources.NotFoundException("No StateLayout emptyLayout is set");
        }
        if (ordinal2 == 2) {
            throw new Resources.NotFoundException("No StateLayout errorLayout is set");
        }
        if (ordinal2 != 3) {
            throw new NoWhenBranchMatchedException();
        }
        throw new Resources.NotFoundException("No StateLayout contentView is set");
    }

    /* renamed from: g */
    public static void m3994g(StateLayout stateLayout, Object obj, boolean z, boolean z2, int i2) {
        Function2<? super StateLayout, Object, Unit> function2;
        if ((i2 & 1) != 0) {
            obj = null;
        }
        if ((i2 & 2) != 0) {
            z = false;
        }
        if ((i2 & 4) != 0) {
            z2 = true;
        }
        Objects.requireNonNull(stateLayout);
        if (!z) {
            stateLayout.m3995h(Status.LOADING, obj);
        }
        if (!z2 || (function2 = stateLayout.f9020f) == null) {
            return;
        }
        function2.invoke(stateLayout, obj);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final Function2<View, Object, Unit> getOnContent() {
        StateConfig stateConfig = StateConfig.f2875a;
        return null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final Function2<View, Object, Unit> getOnEmpty() {
        StateConfig stateConfig = StateConfig.f2875a;
        return null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final Function2<View, Object, Unit> getOnError() {
        StateConfig stateConfig = StateConfig.f2875a;
        return null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final Function2<View, Object, Unit> getOnLoading() {
        StateConfig stateConfig = StateConfig.f2875a;
        return null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final int[] getRetryIds() {
        StateConfig stateConfig = StateConfig.f2875a;
        return null;
    }

    /* renamed from: getClickThrottle, reason: from getter */
    public final long getF9023i() {
        return this.f9023i;
    }

    public final int getEmptyLayout() {
        int i2 = this.f9026l;
        return i2 == -1 ? StateConfig.f2877c : i2;
    }

    public final int getErrorLayout() {
        int i2 = this.f9025k;
        return i2 == -1 ? StateConfig.f2876b : i2;
    }

    /* renamed from: getLoaded, reason: from getter */
    public final boolean getF9022h() {
        return this.f9022h;
    }

    public final int getLoadingLayout() {
        int i2 = this.f9027m;
        return i2 == -1 ? StateConfig.f2878d : i2;
    }

    @NotNull
    /* renamed from: getStateChangedHandler, reason: from getter */
    public final StateChangedHandler getF9024j() {
        return this.f9024j;
    }

    @NotNull
    /* renamed from: getStatus, reason: from getter */
    public final Status getF9021g() {
        return this.f9021g;
    }

    /* renamed from: h */
    public final void m3995h(Status status, Object obj) {
        Status status2 = this.f9021g;
        if (status2 == status) {
            StatusInfo statusInfo = this.f9019e.get(status2);
            if (Intrinsics.areEqual(statusInfo != null ? statusInfo.f2888b : null, obj)) {
                return;
            }
        }
        final C3248a c3248a = new C3248a(status, obj);
        if (Intrinsics.areEqual(Looper.myLooper(), Looper.getMainLooper())) {
            c3248a.invoke();
        } else {
            new Handler(Looper.getMainLooper()).post(new Runnable() { // from class: b.i.b.a
                @Override // java.lang.Runnable
                public final void run() {
                    Function0 block = Function0.this;
                    int i2 = StateLayout.f9018c;
                    Intrinsics.checkNotNullParameter(block, "$block");
                    block.invoke();
                }
            });
        }
    }

    @Override // android.view.View
    public void onFinishInflate() {
        super.onFinishInflate();
        if (getChildCount() > 1 || getChildCount() == 0) {
            throw new UnsupportedOperationException("StateLayout only have one child view");
        }
        if (this.f9019e.size() == 0) {
            View view = getChildAt(0);
            Intrinsics.checkNotNullExpressionValue(view, "view");
            setContent(view);
        }
    }

    public final void setClickThrottle(long j2) {
        this.f9023i = j2;
    }

    public final void setContent(@NotNull View view) {
        Intrinsics.checkNotNullParameter(view, "view");
        this.f9019e.put(Status.CONTENT, new StatusInfo(view, null));
    }

    public final void setEmptyLayout(int i2) {
        if (this.f9026l != i2) {
            this.f9019e.remove(Status.EMPTY);
            this.f9026l = i2;
        }
    }

    public final void setErrorLayout(int i2) {
        if (this.f9025k != i2) {
            this.f9019e.remove(Status.ERROR);
            this.f9025k = i2;
        }
    }

    public final void setLoaded(boolean z) {
        this.f9022h = z;
    }

    public final void setLoadingLayout(int i2) {
        if (this.f9027m != i2) {
            this.f9019e.remove(Status.LOADING);
            this.f9027m = i2;
        }
    }

    public final void setStateChangedHandler(@NotNull StateChangedHandler stateChangedHandler) {
        Intrinsics.checkNotNullParameter(stateChangedHandler, "<set-?>");
        this.f9024j = stateChangedHandler;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    @JvmOverloads
    public StateLayout(@NotNull Context context, @Nullable AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        Intrinsics.checkNotNullParameter(context, "context");
        this.f9019e = new ArrayMap<>();
        this.f9021g = Status.CONTENT;
        this.f9023i = StateConfig.f2880f;
        this.f9024j = StateConfig.f2879e;
        this.f9025k = -1;
        this.f9026l = -1;
        this.f9027m = -1;
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.StateLayout);
        Intrinsics.checkNotNullExpressionValue(obtainStyledAttributes, "context.obtainStyledAttr… R.styleable.StateLayout)");
        try {
            setEmptyLayout(obtainStyledAttributes.getResourceId(R$styleable.StateLayout_empty_layout, -1));
            setErrorLayout(obtainStyledAttributes.getResourceId(R$styleable.StateLayout_error_layout, -1));
            setLoadingLayout(obtainStyledAttributes.getResourceId(R$styleable.StateLayout_loading_layout, -1));
        } finally {
            obtainStyledAttributes.recycle();
        }
    }
}

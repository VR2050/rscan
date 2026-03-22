package com.drake.statelayout;

import androidx.annotation.LayoutRes;
import com.drake.statelayout.StateChangedHandler;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata(m5310d1 = {"\u0000@\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0010\t\n\u0002\b\u0006\n\u0002\u0010\b\n\u0002\b\u000e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\u0018\u0002\n\u0002\b\u000e\n\u0002\u0010\u0015\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\t\bÆ\u0002\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002J)\u0010\u0019\u001a\u00020\u001c2\u001f\u00108\u001a\u001b\u0012\u0004\u0012\u00020\u001b\u0012\u0006\u0012\u0004\u0018\u00010\u0001\u0012\u0004\u0012\u00020\u001c0\u001a¢\u0006\u0002\b\u001dH\u0007J)\u0010\"\u001a\u00020\u001c2\u001f\u00108\u001a\u001b\u0012\u0004\u0012\u00020\u001b\u0012\u0006\u0012\u0004\u0018\u00010\u0001\u0012\u0004\u0012\u00020\u001c0\u001a¢\u0006\u0002\b\u001dH\u0007J)\u0010%\u001a\u00020\u001c2\u001f\u00108\u001a\u001b\u0012\u0004\u0012\u00020\u001b\u0012\u0006\u0012\u0004\u0018\u00010\u0001\u0012\u0004\u0012\u00020\u001c0\u001a¢\u0006\u0002\b\u001dH\u0007J)\u0010(\u001a\u00020\u001c2\u001f\u00108\u001a\u001b\u0012\u0004\u0012\u00020\u001b\u0012\u0006\u0012\u0004\u0018\u00010\u0001\u0012\u0004\u0012\u00020\u001c0\u001a¢\u0006\u0002\b\u001dH\u0007J\u0016\u00109\u001a\u00020\u001c2\f\b\u0001\u0010:\u001a\u00020,\"\u00020\u000bH\u0007R$\u0010\u0003\u001a\u00020\u00048\u0006@\u0006X\u0087\u000e¢\u0006\u0014\n\u0000\u0012\u0004\b\u0005\u0010\u0002\u001a\u0004\b\u0006\u0010\u0007\"\u0004\b\b\u0010\tR$\u0010\n\u001a\u00020\u000b8\u0006@\u0006X\u0087\u000e¢\u0006\u0014\n\u0000\u0012\u0004\b\f\u0010\u0002\u001a\u0004\b\r\u0010\u000e\"\u0004\b\u000f\u0010\u0010R$\u0010\u0011\u001a\u00020\u000b8\u0006@\u0006X\u0087\u000e¢\u0006\u0014\n\u0000\u0012\u0004\b\u0012\u0010\u0002\u001a\u0004\b\u0013\u0010\u000e\"\u0004\b\u0014\u0010\u0010R$\u0010\u0015\u001a\u00020\u000b8\u0006@\u0006X\u0087\u000e¢\u0006\u0014\n\u0000\u0012\u0004\b\u0016\u0010\u0002\u001a\u0004\b\u0017\u0010\u000e\"\u0004\b\u0018\u0010\u0010R5\u0010\u0019\u001a\u001d\u0012\u0004\u0012\u00020\u001b\u0012\u0006\u0012\u0004\u0018\u00010\u0001\u0012\u0004\u0012\u00020\u001c\u0018\u00010\u001a¢\u0006\u0002\b\u001dX\u0080\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u001e\u0010\u001f\"\u0004\b \u0010!R5\u0010\"\u001a\u001d\u0012\u0004\u0012\u00020\u001b\u0012\u0006\u0012\u0004\u0018\u00010\u0001\u0012\u0004\u0012\u00020\u001c\u0018\u00010\u001a¢\u0006\u0002\b\u001dX\u0080\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b#\u0010\u001f\"\u0004\b$\u0010!R5\u0010%\u001a\u001d\u0012\u0004\u0012\u00020\u001b\u0012\u0006\u0012\u0004\u0018\u00010\u0001\u0012\u0004\u0012\u00020\u001c\u0018\u00010\u001a¢\u0006\u0002\b\u001dX\u0080\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b&\u0010\u001f\"\u0004\b'\u0010!R5\u0010(\u001a\u001d\u0012\u0004\u0012\u00020\u001b\u0012\u0006\u0012\u0004\u0018\u00010\u0001\u0012\u0004\u0012\u00020\u001c\u0018\u00010\u001a¢\u0006\u0002\b\u001dX\u0080\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b)\u0010\u001f\"\u0004\b*\u0010!R\u001c\u0010+\u001a\u0004\u0018\u00010,X\u0080\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b-\u0010.\"\u0004\b/\u00100R$\u00101\u001a\u0002028\u0006@\u0006X\u0087\u000e¢\u0006\u0014\n\u0000\u0012\u0004\b3\u0010\u0002\u001a\u0004\b4\u00105\"\u0004\b6\u00107¨\u0006;"}, m5311d2 = {"Lcom/drake/statelayout/StateConfig;", "", "()V", "clickThrottle", "", "getClickThrottle$annotations", "getClickThrottle", "()J", "setClickThrottle", "(J)V", "emptyLayout", "", "getEmptyLayout$annotations", "getEmptyLayout", "()I", "setEmptyLayout", "(I)V", "errorLayout", "getErrorLayout$annotations", "getErrorLayout", "setErrorLayout", "loadingLayout", "getLoadingLayout$annotations", "getLoadingLayout", "setLoadingLayout", "onContent", "Lkotlin/Function2;", "Landroid/view/View;", "", "Lkotlin/ExtensionFunctionType;", "getOnContent$statelayout_release", "()Lkotlin/jvm/functions/Function2;", "setOnContent$statelayout_release", "(Lkotlin/jvm/functions/Function2;)V", "onEmpty", "getOnEmpty$statelayout_release", "setOnEmpty$statelayout_release", "onError", "getOnError$statelayout_release", "setOnError$statelayout_release", "onLoading", "getOnLoading$statelayout_release", "setOnLoading$statelayout_release", "retryIds", "", "getRetryIds$statelayout_release", "()[I", "setRetryIds$statelayout_release", "([I)V", "stateChangedHandler", "Lcom/drake/statelayout/StateChangedHandler;", "getStateChangedHandler$annotations", "getStateChangedHandler", "()Lcom/drake/statelayout/StateChangedHandler;", "setStateChangedHandler", "(Lcom/drake/statelayout/StateChangedHandler;)V", "block", "setRetryIds", "ids", "statelayout_release"}, m5312k = 1, m5313mv = {1, 6, 0}, m5315xi = 48)
/* renamed from: b.i.b.c, reason: from Kotlin metadata */
/* loaded from: classes.dex */
public final class StateConfig {

    /* renamed from: a */
    @NotNull
    public static final StateConfig f2875a = null;

    /* renamed from: b */
    @LayoutRes
    public static int f2876b = -1;

    /* renamed from: c */
    @LayoutRes
    public static int f2877c = -1;

    /* renamed from: d */
    @LayoutRes
    public static int f2878d = -1;

    /* renamed from: e */
    @NotNull
    public static StateChangedHandler f2879e = StateChangedHandler.a.f2874a;

    /* renamed from: f */
    public static long f2880f = 500;
}
